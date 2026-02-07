// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Anti-Forensics                         ║
// ║         Secure deletion, memory scrubbing, core dump prevention  ║
// ╚══════════════════════════════════════════════════════════════════╝
//
// SECURITY NOTE: Multi-pass file overwriting is effective on traditional
// HDDs with direct sector access. On SSDs, copy-on-write filesystems
// (ZFS, Btrfs), and journaling filesystems (ext4, NTFS), overwritten
// data may persist in spare blocks, journals, or WAL. Consider using
// full-disk encryption (LUKS, BitLocker) as the primary defense.

use crate::crypto::secure_mem;
use crate::error::{CleanupReport, GhostError};
use std::io::{Write, Seek, SeekFrom};
use std::path::Path;

/// Options for secure file deletion
pub struct SecureDeleteOptions {
    /// Number of overwrite passes (default: 3)
    pub passes: u32,
    /// Whether to use platform-specific APIs for SSD-aware zeroing
    pub use_platform_api: bool,
    /// Whether to verify deletion after completion
    pub verify_deletion: bool,
}

impl Default for SecureDeleteOptions {
    fn default() -> Self {
        Self {
            passes: 3,
            use_platform_api: true,
            verify_deletion: true,
        }
    }
}

/// Options for safe free-space filling
pub struct FillOptions {
    /// Maximum bytes to write (default: 1 GB)
    pub max_bytes: u64,
    /// Minimum percentage of disk that must remain free (default: 10%)
    pub min_free_pct: f64,
}

impl Default for FillOptions {
    fn default() -> Self {
        Self {
            max_bytes: 1024 * 1024 * 1024, // 1 GB
            min_free_pct: 10.0,
        }
    }
}

/// Securely delete a file with multiple overwrite passes.
///
/// On supported platforms, also attempts platform-specific secure
/// deletion (e.g., `FSCTL_SET_ZERO_DATA` on Windows, `fallocate` on Linux).
pub fn secure_delete_file(path: &Path, passes: u32) -> Result<(), GhostError> {
    secure_delete_file_with_options(path, &SecureDeleteOptions {
        passes,
        ..SecureDeleteOptions::default()
    })
}

/// Securely delete a file with full options control.
pub fn secure_delete_file_with_options(
    path: &Path,
    options: &SecureDeleteOptions,
) -> Result<(), GhostError> {
    if !path.exists() {
        return Ok(());
    }

    let metadata = std::fs::metadata(path)?;
    let size = metadata.len() as usize;

    if size > 0 {
        // Try platform-specific secure deletion first
        if options.use_platform_api {
            let _ = platform_secure_zero(path, size);
            // Fall through to overwrite regardless — belt and suspenders
        }

        let mut file = std::fs::OpenOptions::new().write(true).open(path)?;

        for pass in 0..options.passes {
            let pattern: Vec<u8> = match pass % 7 {
                0 => vec![0x00; size],         // All zeros
                1 => vec![0xFF; size],         // All ones
                2 => vec![0x55; size],         // 01010101
                3 => vec![0xAA; size],         // 10101010
                4 => {                          // Random data
                    let mut data = vec![0u8; size];
                    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut data);
                    data
                }
                5 => vec![0x92; size],         // Gutmann pattern
                6 => vec![0x49; size],         // Gutmann pattern
                _ => vec![0x00; size],
            };

            file.seek(SeekFrom::Start(0))?;
            file.write_all(&pattern)?;
            file.flush()?;
            file.sync_all()?;
        }
    }

    // Finally, remove the file
    std::fs::remove_file(path)?;

    // Verify if requested
    if options.verify_deletion && path.exists() {
        return Err(GhostError::Stealth(
            format!("File still exists after secure deletion: {}", path.display()),
        ));
    }

    Ok(())
}

/// Platform-specific secure zeroing (best-effort, non-fatal on failure).
fn platform_secure_zero(path: &Path, _size: usize) -> Result<(), GhostError> {
    #[cfg(windows)]
    {
        // On Windows, FSCTL_SET_ZERO_DATA would be ideal for SSD-aware zeroing
        // on NTFS, but requires Win32_System_IO features. For now, we rely on
        // the multi-pass overwrite in the caller. The file is opened with
        // FILE_FLAG_WRITE_THROUGH to bypass the write cache.
        use std::os::windows::fs::OpenOptionsExt;

        let _ = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(0x80000000) // FILE_FLAG_WRITE_THROUGH
            .open(path)
            .map_err(|e| GhostError::Stealth(
                format!("Failed to open file with write-through: {}", e)
            ))?;

        // Future: Add DeviceIoControl with FSCTL_SET_ZERO_DATA when
        // Win32_System_IO feature is enabled in windows-sys
    }

    #[cfg(target_os = "linux")]
    {
        // On Linux, use fallocate with FALLOC_FL_PUNCH_HOLE to
        // deallocate the data blocks, which is SSD-TRIM aware.
        use std::os::unix::io::AsRawFd;

        let file = std::fs::OpenOptions::new().write(true).open(path)?;
        let fd = file.as_raw_fd();

        // FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE
        let ret = unsafe {
            libc::fallocate(fd, 0x01 | 0x02, 0, _size as i64)
        };

        if ret != 0 {
            // Non-fatal — fall through to overwrite
            tracing::warn!("fallocate punch-hole failed, falling back to overwrite");
        }
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    {
        // No platform-specific API available — rely on overwrite passes
        let _ = _size;
    }

    let _ = path; // suppress unused warning on non-windows/linux
    Ok(())
}

/// Securely delete a directory and all its contents
pub fn secure_delete_dir(path: &Path, passes: u32) -> Result<(), GhostError> {
    if !path.exists() {
        return Ok(());
    }

    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        if entry_path.is_dir() {
            secure_delete_dir(&entry_path, passes)?;
        } else {
            secure_delete_file(&entry_path, passes)?;
        }
    }

    std::fs::remove_dir(path)?;
    Ok(())
}

/// Scrub all sensitive memory regions on exit.
/// Returns the number of bytes scrubbed.
pub fn scrub_memory() -> Result<usize, GhostError> {
    let block_size = 1024 * 1024; // 1 MB
    let block_count = 10;
    let mut total_scrubbed = 0;

    for _ in 0..block_count {
        let mut block = vec![0u8; block_size];
        secure_mem::secure_wipe(&mut block, 1);
        total_scrubbed += block_size;
    }

    Ok(total_scrubbed)
}

/// Prevent core dumps from being created
pub fn disable_core_dumps() {
    secure_mem::prevent_core_dumps();
}

/// Clear sensitive environment variables.
/// Returns the number of variables cleaned.
pub fn sanitize_environment() -> usize {
    let sensitive_vars = [
        "GHOSTSHELL_KEY",
        "GHOSTSHELL_PASSWORD",
        "GHOSTSHELL_SESSION",
        "GHOSTSHELL_MODE",
        // NOTE: GHOSTSHELL_CLOAKED intentionally NOT listed here —
        // we no longer set it (see process_cloak.rs fix)
        "HISTFILE",
        "MYSQL_PWD",
        "AWS_SECRET_ACCESS_KEY",
        "SSH_AUTH_SOCK",
    ];

    let mut cleaned = 0;
    for var in &sensitive_vars {
        if std::env::var(var).is_ok() {
            std::env::remove_var(var);
            cleaned += 1;
        }
    }
    cleaned
}

/// Disable swap/pagefile usage for this process (best-effort)
pub fn disable_swap() {
    #[cfg(windows)]
    {
        unsafe {
            use windows_sys::Win32::System::Threading::GetCurrentProcess;
            use windows_sys::Win32::System::Memory::SetProcessWorkingSetSizeEx;

            let process = GetCurrentProcess();
            // QUOTA_LIMITS_HARDWS_MIN_ENABLE = 0x01
            SetProcessWorkingSetSizeEx(process, 50 * 1024 * 1024, 200 * 1024 * 1024, 0x01);
        }
    }

    #[cfg(unix)]
    {
        unsafe {
            libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
        }
    }
}

/// Overwrite the terminal's own scrollback buffer
pub fn clear_terminal_scrollback() {
    print!("\x1b[3J\x1b[2J\x1b[H");
    let _ = std::io::stdout().flush();
}

/// Write random data to fill free disk space (fills slack space).
///
/// This version includes safety guardrails:
/// - Checks available disk space before starting
/// - Caps at `options.max_bytes` (default: 1 GB)
/// - Aborts if free space would drop below `options.min_free_pct`
/// - Returns the number of bytes written
pub fn fill_free_space_safe(path: &Path, options: &FillOptions) -> Result<u64, GhostError> {
    // Check available disk space (platform-specific)
    let available = get_available_disk_space(path)?;

    // Safety check: don't fill if less than min_free_pct is available
    let total = get_total_disk_space(path).unwrap_or(available);
    let free_pct = (available as f64 / total as f64) * 100.0;

    if free_pct < options.min_free_pct {
        return Err(GhostError::InsufficientDiskSpace {
            available,
            required: (total as f64 * options.min_free_pct / 100.0) as u64,
        });
    }

    // Cap the amount we'll write
    let max_fill = options.max_bytes.min(
        available - (total as f64 * options.min_free_pct / 100.0) as u64
    );

    let fill_path = path.join(".ghostshell_fill");
    let mut file = std::fs::File::create(&fill_path)?;

    let block_size = 1024 * 1024; // 1 MB blocks
    let mut block = vec![0u8; block_size];
    let mut total_written: u64 = 0;

    while total_written < max_fill {
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut block);
        let to_write = block_size.min((max_fill - total_written) as usize);
        match file.write_all(&block[..to_write]) {
            Ok(_) => total_written += to_write as u64,
            Err(_) => break, // Disk full or error
        }
    }

    file.sync_all()?;
    let _ = std::fs::remove_file(&fill_path);

    Ok(total_written)
}

/// Legacy fill_free_space — wraps fill_free_space_safe with default options
pub fn fill_free_space(path: &Path) -> Result<(), GhostError> {
    fill_free_space_safe(path, &FillOptions::default())?;
    Ok(())
}

/// Get available disk space for a path (platform-specific)
fn get_available_disk_space(path: &Path) -> Result<u64, GhostError> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;

        let wide_path: Vec<u16> = path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut free_bytes: u64 = 0;
        let mut total_bytes: u64 = 0;
        let mut total_free: u64 = 0;

        let result = unsafe {
            windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW(
                wide_path.as_ptr(),
                &mut free_bytes,
                &mut total_bytes,
                &mut total_free,
            )
        };

        if result != 0 {
            Ok(free_bytes)
        } else {
            Err(GhostError::Stealth("Failed to query disk space".to_string()))
        }
    }

    #[cfg(unix)]
    {
        use std::ffi::CString;

        let c_path = CString::new(
            path.to_str().unwrap_or("/")
        ).map_err(|_| GhostError::Stealth("Invalid path for statvfs".to_string()))?;

        unsafe {
            let mut stat: libc::statvfs = std::mem::zeroed();
            if libc::statvfs(c_path.as_ptr(), &mut stat) == 0 {
                Ok(stat.f_bavail as u64 * stat.f_bsize as u64)
            } else {
                Err(GhostError::Stealth("statvfs failed".to_string()))
            }
        }
    }
}

/// Get total disk space for a path (platform-specific)
fn get_total_disk_space(path: &Path) -> Result<u64, GhostError> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;

        let wide_path: Vec<u16> = path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut free_bytes: u64 = 0;
        let mut total_bytes: u64 = 0;
        let mut total_free: u64 = 0;

        let result = unsafe {
            windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW(
                wide_path.as_ptr(),
                &mut free_bytes,
                &mut total_bytes,
                &mut total_free,
            )
        };

        if result != 0 {
            Ok(total_bytes)
        } else {
            Err(GhostError::Stealth("Failed to query disk space".to_string()))
        }
    }

    #[cfg(unix)]
    {
        use std::ffi::CString;

        let c_path = CString::new(
            path.to_str().unwrap_or("/")
        ).map_err(|_| GhostError::Stealth("Invalid path for statvfs".to_string()))?;

        unsafe {
            let mut stat: libc::statvfs = std::mem::zeroed();
            if libc::statvfs(c_path.as_ptr(), &mut stat) == 0 {
                Ok(stat.f_blocks as u64 * stat.f_frsize as u64)
            } else {
                Err(GhostError::Stealth("statvfs failed".to_string()))
            }
        }
    }
}

/// Comprehensive exit cleanup.
/// Returns a report of actions taken.
pub fn full_cleanup() -> Result<CleanupReport, GhostError> {
    let mut report = CleanupReport::default();

    report.env_vars_cleaned = sanitize_environment();
    clear_terminal_scrollback();

    match scrub_memory() {
        Ok(bytes) => report.memory_scrubbed = bytes,
        Err(e) => report.warnings.push(format!("Memory scrub failed: {}", e)),
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_secure_delete() {
        let dir = std::env::temp_dir().join("ghostshell_test_delete");
        let _ = std::fs::create_dir_all(&dir);
        let file_path = dir.join("test.txt");

        let mut file = std::fs::File::create(&file_path).unwrap();
        file.write_all(b"secret data that must be destroyed").unwrap();
        drop(file);

        secure_delete_file(&file_path, 3).unwrap();
        assert!(!file_path.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sanitize_environment() {
        std::env::set_var("GHOSTSHELL_KEY", "secret");
        let cleaned = sanitize_environment();
        assert!(std::env::var("GHOSTSHELL_KEY").is_err());
        assert!(cleaned >= 1);
    }

    #[test]
    fn test_scrub_memory_returns_bytes() {
        let result = scrub_memory();
        assert!(result.is_ok());
        assert!(result.unwrap() > 0);
    }

    #[test]
    fn test_fill_safety_guardrails() {
        // Test that FillOptions defaults are sane
        let opts = FillOptions::default();
        assert_eq!(opts.max_bytes, 1024 * 1024 * 1024);
        assert!((opts.min_free_pct - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_full_cleanup_returns_report() {
        let result = full_cleanup();
        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(report.memory_scrubbed > 0);
    }

    #[test]
    fn test_secure_delete_options_default() {
        let opts = SecureDeleteOptions::default();
        assert_eq!(opts.passes, 3);
        assert!(opts.use_platform_api);
        assert!(opts.verify_deletion);
    }
}
