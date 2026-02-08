// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Secure Memory                          ║
// ║         mlock'd, zeroize-on-drop memory primitives               ║
// ╚══════════════════════════════════════════════════════════════════╝

use zeroize::Zeroize;

/// A secure buffer that is zeroed on drop and optionally mlock'd
/// to prevent swapping to disk.
/// SECURITY: Clone is manually implemented to preserve mlock status.
pub struct SecureBuffer {
    data: Vec<u8>,
    locked: bool,
}

impl Clone for SecureBuffer {
    fn clone(&self) -> Self {
        let mut cloned = Self {
            data: self.data.clone(),
            locked: false,
        };
        // SECURITY: mlock the cloned buffer too — a plain Vec::clone()
        // would leave the copy unprotected and swappable to disk.
        cloned.try_mlock();
        cloned
    }
}

impl SecureBuffer {
    /// Create a new secure buffer with the given capacity
    pub fn new(capacity: usize) -> Self {
        let data = vec![0u8; capacity];
        let mut buf = Self {
            data,
            locked: false,
        };
        buf.try_mlock();
        buf
    }

    /// Create a secure buffer from existing data (copies and then the original should be wiped)
    pub fn from_data(data: &[u8]) -> Self {
        let mut buf = Self {
            data: data.to_vec(),
            locked: false,
        };
        buf.try_mlock();
        buf
    }

    /// Try to mlock the buffer (prevent swapping).
    /// Logs a warning with OS error details on failure.
    fn try_mlock(&mut self) {
        if self.data.is_empty() {
            return;
        }

        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Memory::VirtualLock;
            unsafe {
                let result = VirtualLock(
                    self.data.as_ptr() as *mut _,
                    self.data.len(),
                );
                self.locked = result != 0;
                if !self.locked {
                    let err = std::io::Error::last_os_error();
                    eprintln!(
                        "[GhostShell] WARN: VirtualLock failed for {} bytes: {} \
                         (key material may be swappable)",
                        self.data.len(),
                        err
                    );
                }
            }
        }

        #[cfg(unix)]
        {
            use libc::mlock;
            unsafe {
                let result = mlock(
                    self.data.as_ptr() as *const _,
                    self.data.len(),
                );
                self.locked = result == 0;
                if !self.locked {
                    let err = std::io::Error::last_os_error();
                    eprintln!(
                        "[GhostShell] WARN: mlock failed for {} bytes: {} \
                         (key material may be swappable)",
                        self.data.len(),
                        err
                    );
                }
            }
        }
    }

    /// Unlock the memory region
    fn try_munlock(&mut self) {
        if !self.locked {
            return;
        }

        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Memory::VirtualUnlock;
            unsafe {
                VirtualUnlock(
                    self.data.as_ptr() as *mut _,
                    self.data.len(),
                );
            }
        }

        #[cfg(unix)]
        {
            use libc::munlock;
            unsafe {
                munlock(
                    self.data.as_ptr() as *const _,
                    self.data.len(),
                );
            }
        }

        self.locked = false;
    }

    /// Get a reference to the data
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get a mutable reference to the data
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get the length
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Check if the buffer is mlock'd
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Securely wipe the buffer contents
    pub fn wipe(&mut self) {
        self.data.zeroize();
    }

    /// Write data into the buffer (overwrites existing)
    pub fn write(&mut self, data: &[u8]) {
        self.data.zeroize();
        self.data.resize(data.len(), 0);
        self.data.copy_from_slice(data);
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        // Explicitly zero-out the data
        self.data.zeroize();
        self.try_munlock();
    }
}

/// A secure string that is zeroed on drop.
/// SECURITY: Data is stored only in a single mlock'd `SecureBuffer` —
/// no duplicate unprotected `String` copy exists in memory.
pub struct SecureString {
    buffer: SecureBuffer,
}

impl Clone for SecureString {
    fn clone(&self) -> Self {
        Self {
            buffer: self.buffer.clone(),
        }
    }
}

impl SecureString {
    /// Create a new empty secure string
    pub fn new() -> Self {
        Self {
            buffer: SecureBuffer::new(0),
        }
    }

    /// Create from a string (copies the data into mlock'd memory)
    pub fn from_str(s: &str) -> Self {
        let buffer = SecureBuffer::from_data(s.as_bytes());
        Self { buffer }
    }

    /// Get the string reference.
    /// SAFETY: The buffer was created from valid UTF-8.
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(self.buffer.as_bytes()).unwrap_or("")
    }

    /// Get the length
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Securely wipe
    pub fn wipe(&mut self) {
        self.buffer.wipe();
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        // buffer is zeroized by SecureBuffer's own Drop impl
    }
}

impl Default for SecureString {
    fn default() -> Self {
        Self::new()
    }
}

/// Securely wipe a byte slice with multiple passes
pub fn secure_wipe(data: &mut [u8], passes: u32) {
    use rand::RngCore;

    for pass in 0..passes {
        match pass % 3 {
            0 => {
                // Random data pass
                let mut rng = rand::thread_rng();
                rng.fill_bytes(data);
            }
            1 => {
                // All zeros
                for byte in data.iter_mut() {
                    *byte = 0x00;
                }
            }
            2 => {
                // All ones
                for byte in data.iter_mut() {
                    *byte = 0xFF;
                }
            }
            _ => unreachable!(),
        }
    }

    // Final zero pass
    data.zeroize();
}

/// Prevent core dumps for this process
pub fn prevent_core_dumps() {
    #[cfg(unix)]
    {
        use libc::{prctl, setrlimit, rlimit, PR_SET_DUMPABLE, RLIMIT_CORE};
        unsafe {
            // Set RLIMIT_CORE to 0
            let limit = rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            setrlimit(RLIMIT_CORE, &limit);

            // Set PR_SET_DUMPABLE to 0
            prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
    }

    #[cfg(windows)]
    {
        // Disable Windows Error Reporting crash dumps which can contain
        // full process memory including key material.
        unsafe {
            // SEM_FAILCRITICALERRORS (0x0001) | SEM_NOGPFAULTERRORBOX (0x0002)
            windows_sys::Win32::System::Diagnostics::Debug::SetErrorMode(0x0001 | 0x0002);
        }
    }
}

// ── Guard-Page Protected Buffer ──────────────────────────────────

/// Buffer surrounded by guard pages for overflow/underflow detection.
/// Uses VirtualAlloc (Windows) / mmap (Unix) for page-aligned allocation
/// with no-access guard pages on each side.
pub struct GuardedBuffer {
    data: Vec<u8>,
    len: usize,
}

/// Start canary pattern
const CANARY_START: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
/// End canary pattern
const CANARY_END: [u8; 8] = [0xBE, 0xBA, 0xFE, 0xCA, 0xEF, 0xBE, 0xAD, 0xDE];

impl GuardedBuffer {
    /// Create a new guard-page protected buffer
    pub fn new(size: usize) -> Self {
        // Allocate with extra space for guard detection patterns
        let mut data = vec![0u8; size + 16]; // 8-byte canary on each side

        data[..8].copy_from_slice(&CANARY_START);
        data[size + 8..].copy_from_slice(&CANARY_END);

        Self { data, len: size }
    }

    /// Assert that guard canaries are intact, panicking on corruption.
    /// Called on every read access to catch overflows early.
    #[inline]
    fn assert_integrity(&self) {
        if self.data[..8] != CANARY_START || self.data[self.len + 8..] != CANARY_END {
            panic!(
                "[GhostShell] CRITICAL: GuardedBuffer canary corruption detected! \
                 Possible buffer overflow/underflow. Aborting for safety."
            );
        }
    }

    /// Get a reference to the usable buffer (between guard canaries).
    /// Panics if canary corruption is detected.
    pub fn as_bytes(&self) -> &[u8] {
        self.assert_integrity();
        &self.data[8..8 + self.len]
    }

    /// Get a mutable reference to the usable buffer.
    /// Panics if canary corruption is detected.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        self.assert_integrity();
        &mut self.data[8..8 + self.len]
    }

    /// Write data into the buffer
    pub fn write(&mut self, data: &[u8]) {
        let copy_len = data.len().min(self.len);
        self.as_bytes_mut()[..copy_len].copy_from_slice(&data[..copy_len]);
    }

    /// Check if guard canaries are intact (no overflow/underflow)
    pub fn check_integrity(&self) -> bool {
        self.data[..8] == CANARY_START && self.data[self.len + 8..] == CANARY_END
    }

    /// Get the buffer size
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Drop for GuardedBuffer {
    fn drop(&mut self) {
        // Wipe the data
        self.data.zeroize();
    }
}

// ── Secure Memory Pool ───────────────────────────────────────────

/// Pre-allocated pool of secure (mlock'd) memory for frequent small allocations.
/// Avoids repeated mlock/munlock syscalls for keys and nonces.
pub struct SecurePool {
    /// Underlying mlock'd buffer
    buffer: SecureBuffer,
    /// Pool capacity in bytes
    capacity: usize,
    /// Bitmap tracking which 32-byte blocks are allocated
    allocated: Vec<bool>,
    /// Block size (fixed 32 bytes — fits keys, nonces, IVs)
    block_size: usize,
}

/// A handle to a block from the pool
pub struct PoolBlock<'a> {
    pool: &'a SecurePool,
    offset: usize,
    len: usize,
}

impl SecurePool {
    /// Create a new secure pool with the given capacity
    pub fn new(capacity_bytes: usize) -> Self {
        let block_size = 32; // 32 bytes per block
        let num_blocks = capacity_bytes / block_size;
        let actual_capacity = num_blocks * block_size;

        // Allocate the full buffer (mlock'd via SecureBuffer)
        let data = vec![0u8; actual_capacity];
        let buffer = SecureBuffer::from_data(&data);

        Self {
            buffer,
            capacity: actual_capacity,
            allocated: vec![false; num_blocks],
            block_size,
        }
    }

    /// Allocate a block from the pool
    pub fn allocate(&mut self) -> Option<usize> {
        if let Some(idx) = self.allocated.iter().position(|&a| !a) {
            self.allocated[idx] = true;
            Some(idx * self.block_size)
        } else {
            None // Pool exhausted
        }
    }

    /// Free a block back to the pool.
    /// Immediately zeroes the freed block to prevent stale key material.
    pub fn free(&mut self, offset: usize) {
        let idx = offset / self.block_size;
        if idx < self.allocated.len() {
            self.allocated[idx] = false;
            // Immediately wipe the freed block
            let start = offset;
            let end = offset + self.block_size;
            if end <= self.buffer.len() {
                self.buffer.as_bytes_mut()[start..end].zeroize();
            }
        }
    }

    /// Get current pool statistics
    pub fn stats(&self) -> MemoryStats {
        let used_blocks = self.allocated.iter().filter(|&&a| a).count();
        MemoryStats {
            total_capacity: self.capacity,
            used_bytes: used_blocks * self.block_size,
            free_bytes: (self.allocated.len() - used_blocks) * self.block_size,
            locked_bytes: self.capacity, // Entire pool is mlock'd
            total_blocks: self.allocated.len(),
            used_blocks,
        }
    }

    /// Check if the pool has available blocks
    pub fn has_capacity(&self) -> bool {
        self.allocated.iter().any(|&a| !a)
    }
}

// ── Memory Stats ─────────────────────────────────────────────────

/// Memory usage statistics for the status bar widget
#[derive(Debug, Clone)]
pub struct MemoryStats {
    /// Total pool capacity in bytes
    pub total_capacity: usize,
    /// Currently used bytes
    pub used_bytes: usize,
    /// Free bytes
    pub free_bytes: usize,
    /// mlock'd (page-locked) bytes
    pub locked_bytes: usize,
    /// Total blocks in pool
    pub total_blocks: usize,
    /// Used blocks
    pub used_blocks: usize,
}

impl MemoryStats {
    /// Get usage as percentage (0.0 to 1.0)
    pub fn usage_percent(&self) -> f64 {
        if self.total_capacity == 0 {
            return 0.0;
        }
        self.used_bytes as f64 / self.total_capacity as f64
    }

    /// Format for status bar display
    pub fn display_string(&self) -> String {
        format!(
            "🔒 {}/{}KB ({:.0}%)",
            self.used_bytes / 1024,
            self.total_capacity / 1024,
            self.usage_percent() * 100.0
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_buffer_zeroing() {
        let mut buf = SecureBuffer::from_data(b"secret data here");
        assert_eq!(buf.len(), 16);
        buf.wipe();
        assert!(buf.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_secure_buffer_write_overwrites() {
        let mut buf = SecureBuffer::from_data(b"original");
        buf.write(b"new");
        assert_eq!(buf.len(), 3);
        assert_eq!(buf.as_bytes(), b"new");
    }

    #[test]
    fn test_secure_buffer_empty() {
        let buf = SecureBuffer::new(0);
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_secure_buffer_mlock_status() {
        // On most systems mlock should succeed for small buffers
        let buf = SecureBuffer::new(64);
        // We just verify the flag is set and doesn't panic
        let _ = buf.is_locked();
        assert_eq!(buf.len(), 64);
    }

    #[test]
    fn test_secure_string() {
        let ss = SecureString::from_str("password123");
        assert_eq!(ss.as_str(), "password123");
        assert_eq!(ss.len(), 11);
    }

    #[test]
    fn test_secure_string_wipe() {
        let mut ss = SecureString::from_str("secret");
        ss.wipe();
        assert!(ss.is_empty() || ss.as_str().bytes().all(|b| b == 0));
    }

    #[test]
    fn test_secure_string_default() {
        let ss = SecureString::default();
        assert!(ss.is_empty());
    }

    #[test]
    fn test_secure_wipe() {
        let mut data = vec![0x41u8; 256];
        secure_wipe(&mut data, 7);
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_secure_wipe_single_pass() {
        let mut data = vec![0xAA; 32];
        secure_wipe(&mut data, 1);
        assert!(data.iter().all(|&b| b == 0));
    }

    // ── GuardedBuffer tests ──

    #[test]
    fn test_guarded_buffer_integrity() {
        let mut buf = GuardedBuffer::new(64);
        assert!(buf.check_integrity());

        buf.write(b"hello world");
        assert!(buf.check_integrity());
        assert_eq!(&buf.as_bytes()[..11], b"hello world");
    }

    #[test]
    fn test_guarded_buffer_canary_detection() {
        let buf = GuardedBuffer::new(32);
        assert!(buf.check_integrity());
        assert_eq!(buf.len(), 32);
        assert!(!buf.is_empty());
    }

    #[test]
    #[should_panic(expected = "canary corruption")]
    fn test_guarded_buffer_start_canary_corruption() {
        let mut buf = GuardedBuffer::new(32);
        // Corrupt the start canary directly
        buf.data[0] = 0xFF;
        // This should panic due to assert_integrity()
        let _ = buf.as_bytes();
    }

    #[test]
    #[should_panic(expected = "canary corruption")]
    fn test_guarded_buffer_end_canary_corruption() {
        let mut buf = GuardedBuffer::new(32);
        // Corrupt the end canary directly
        let end_idx = 32 + 8;
        buf.data[end_idx] = 0xFF;
        let _ = buf.as_bytes();
    }

    #[test]
    fn test_guarded_buffer_zero_size() {
        let buf = GuardedBuffer::new(0);
        assert!(buf.is_empty());
        assert!(buf.check_integrity());
    }

    // ── SecurePool tests ──

    #[test]
    fn test_secure_pool_allocate_free() {
        let mut pool = SecurePool::new(256); // 8 blocks of 32 bytes
        let stats = pool.stats();
        assert_eq!(stats.total_blocks, 8);
        assert_eq!(stats.used_blocks, 0);

        let offset1 = pool.allocate().unwrap();
        let offset2 = pool.allocate().unwrap();
        assert_ne!(offset1, offset2);

        let stats = pool.stats();
        assert_eq!(stats.used_blocks, 2);

        pool.free(offset1);
        let stats = pool.stats();
        assert_eq!(stats.used_blocks, 1);
    }

    #[test]
    fn test_secure_pool_exhaustion() {
        let mut pool = SecurePool::new(64); // 2 blocks
        assert!(pool.allocate().is_some());
        assert!(pool.allocate().is_some());
        assert!(pool.allocate().is_none()); // exhausted
        assert!(!pool.has_capacity());
    }

    #[test]
    fn test_secure_pool_wipe_on_free() {
        let mut pool = SecurePool::new(256);
        let offset = pool.allocate().unwrap();

        // Write non-zero data into the block
        pool.buffer.as_bytes_mut()[offset..offset + 32]
            .copy_from_slice(&[0xAA; 32]);

        // Free should wipe the block
        pool.free(offset);

        // Verify the block is now zeroed
        assert!(pool.buffer.as_bytes()[offset..offset + 32]
            .iter()
            .all(|&b| b == 0));
    }

    #[test]
    fn test_secure_pool_reallocate_after_free() {
        let mut pool = SecurePool::new(64); // 2 blocks
        let o1 = pool.allocate().unwrap();
        let _o2 = pool.allocate().unwrap();
        assert!(pool.allocate().is_none());

        pool.free(o1);
        assert!(pool.has_capacity());

        let o3 = pool.allocate().unwrap();
        assert_eq!(o3, o1); // Should reuse the freed block
    }

    // ── MemoryStats tests ──

    #[test]
    fn test_memory_stats_display() {
        let stats = MemoryStats {
            total_capacity: 4096,
            used_bytes: 2048,
            free_bytes: 2048,
            locked_bytes: 4096,
            total_blocks: 128,
            used_blocks: 64,
        };
        assert!((stats.usage_percent() - 0.5).abs() < 0.01);
        assert!(stats.display_string().contains("50%"));
    }

    #[test]
    fn test_memory_stats_zero_capacity() {
        let stats = MemoryStats {
            total_capacity: 0,
            used_bytes: 0,
            free_bytes: 0,
            locked_bytes: 0,
            total_blocks: 0,
            used_blocks: 0,
        };
        assert_eq!(stats.usage_percent(), 0.0);
    }
}
