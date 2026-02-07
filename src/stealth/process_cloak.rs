// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Process Cloaking                       ║
// ║         Hide process identity from system monitoring             ║
// ╚══════════════════════════════════════════════════════════════════╝

use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::GhostError;

/// Internal cloak state — tracked atomically instead of via environment
/// variables (which would be detectable by adversaries).
static CLOAKED: AtomicBool = AtomicBool::new(false);

/// Cloak the current process name.
/// Returns an error if a platform API call fails.
pub fn cloak_process(fake_name: &str) -> Result<(), GhostError> {
    #[cfg(windows)]
    cloak_windows(fake_name)?;

    #[cfg(unix)]
    cloak_unix(fake_name)?;

    CLOAKED.store(true, Ordering::SeqCst);
    Ok(())
}

/// Windows process cloaking
#[cfg(windows)]
fn cloak_windows(fake_name: &str) -> Result<(), GhostError> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    // Set the console title to the fake name
    let wide: Vec<u16> = OsStr::new(fake_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let result = unsafe {
        windows_sys::Win32::System::Console::SetConsoleTitleW(wide.as_ptr())
    };

    if result == 0 {
        return Err(GhostError::Stealth(
            "Failed to set console title for cloaking".to_string(),
        ));
    }

    // Remove any GhostShell-specific environment variables
    // NOTE: We do NOT set GHOSTSHELL_CLOAKED — that would be detectable!
    clean_ghost_env_vars();

    Ok(())
}

/// Unix process cloaking
#[cfg(unix)]
fn cloak_unix(fake_name: &str) -> Result<(), GhostError> {
    use std::ffi::CString;

    // PR_SET_NAME changes /proc/self/comm
    let name = CString::new(fake_name).map_err(|e| {
        GhostError::Stealth(format!("Invalid fake name for cloak: {}", e))
    })?;

    let ret = unsafe {
        libc::prctl(libc::PR_SET_NAME, name.as_ptr(), 0, 0, 0)
    };

    if ret != 0 {
        return Err(GhostError::Stealth(
            "prctl PR_SET_NAME failed during cloaking".to_string(),
        ));
    }

    // Clean up GhostShell environment variables
    clean_ghost_env_vars();

    Ok(())
}

/// Remove all GhostShell-related environment variables.
/// This is called by both cloaking paths to prevent env-based detection.
fn clean_ghost_env_vars() {
    // Remove all known GhostShell environment variables
    let ghost_vars = [
        "GHOSTSHELL_SESSION",
        "GHOSTSHELL_MODE",
        "GHOSTSHELL_CONFIG",
        "GHOSTSHELL_DATA",
        "GHOSTSHELL_LOG",
    ];
    for var in &ghost_vars {
        std::env::remove_var(var);
    }
}

/// Restore the original process name
pub fn uncloak_process() -> Result<(), GhostError> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let name = "GhostShell";
        let wide: Vec<u16> = std::ffi::OsStr::new(name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let result = unsafe {
            windows_sys::Win32::System::Console::SetConsoleTitleW(wide.as_ptr())
        };
        if result == 0 {
            return Err(GhostError::Stealth(
                "Failed to restore console title".to_string(),
            ));
        }
    }

    #[cfg(unix)]
    {
        let name = std::ffi::CString::new("ghostshell").map_err(|e| {
            GhostError::Stealth(format!("Invalid name for uncloak: {}", e))
        })?;
        let ret = unsafe {
            libc::prctl(libc::PR_SET_NAME, name.as_ptr(), 0, 0, 0)
        };
        if ret != 0 {
            return Err(GhostError::Stealth(
                "prctl PR_SET_NAME failed during uncloak".to_string(),
            ));
        }
    }

    CLOAKED.store(false, Ordering::SeqCst);
    Ok(())
}

/// Check if the process appears cloaked.
/// Uses internal atomic state + external system checks for defense-in-depth.
pub fn verify_cloak() -> bool {
    // First check internal state
    if !CLOAKED.load(Ordering::SeqCst) {
        return false;
    }

    // Then verify externally
    #[cfg(windows)]
    {
        let mut buf = [0u16; 256];
        let len = unsafe {
            windows_sys::Win32::System::Console::GetConsoleTitleW(buf.as_mut_ptr(), 256)
        };
        if len > 0 {
            let title = String::from_utf16_lossy(&buf[..len as usize]);
            return !title.to_lowercase().contains("ghost");
        }
        false
    }

    #[cfg(unix)]
    {
        if let Ok(comm) = std::fs::read_to_string("/proc/self/comm") {
            return !comm.trim().to_lowercase().contains("ghost");
        }
        false
    }
}

/// Query whether the process is currently in cloaked state (internal only).
pub fn is_cloaked() -> bool {
    CLOAKED.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloak_and_uncloak() {
        // Just verify these don't panic
        let _ = cloak_process("bash");
        let _ = uncloak_process();
    }

    #[test]
    fn test_cloak_state_tracking() {
        // Reset state
        CLOAKED.store(false, Ordering::SeqCst);
        assert!(!is_cloaked());

        // After cloak attempt, internal state should update
        let _ = cloak_process("bash");
        assert!(is_cloaked());

        let _ = uncloak_process();
        assert!(!is_cloaked());
    }

    #[test]
    fn test_no_ghost_env_var_set() {
        let _ = cloak_process("bash");
        // Verify we do NOT set the detectable GHOSTSHELL_CLOAKED variable
        assert!(std::env::var("GHOSTSHELL_CLOAKED").is_err());
    }
}
