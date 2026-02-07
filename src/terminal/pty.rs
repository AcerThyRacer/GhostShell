// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — PTY Management                         ║
// ║         Cross-platform real pseudo-terminal via portable-pty     ║
// ╚══════════════════════════════════════════════════════════════════╝
//
// SECURITY FIX: Previously used `Command::new().stdin(Stdio::piped())`
// which does NOT create a real PTY — interactive programs (vim, htop,
// ssh) would break, and there was no SIGWINCH/resize support.
// Now uses `portable-pty` which provides real ConPTY (Windows) and
// openpty/forkpty (Unix).

use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};
use std::io::{self, Read, Write};
use uuid::Uuid;

use crate::error::GhostError;

/// Represents a real pseudo-terminal session
pub struct PtySession {
    pub id: Uuid,
    pub shell: String,
    pub alive: bool,
    /// The master side of the PTY pair (we read/write here)
    master: Box<dyn MasterPty + Send>,
    /// Writer to the master PTY (for sending input to the child)
    writer: Box<dyn Write + Send>,
    /// Reader from the master PTY (for reading child output)
    reader: Option<Box<dyn Read + Send>>,
    /// Handle to the child process
    child: Option<Box<dyn portable_pty::Child + Send + Sync>>,
}

impl PtySession {
    /// Spawn a new real PTY with the given shell and dimensions.
    pub fn spawn(shell: &str, cols: u16, rows: u16) -> Result<Self, GhostError> {
        let pty_system = native_pty_system();

        let pty_pair = pty_system
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| GhostError::Pty(format!("Failed to open PTY: {}", e)))?;

        let mut cmd = CommandBuilder::new(shell);
        cmd.env("TERM", "xterm-256color");

        let child = pty_pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| GhostError::Pty(format!("Failed to spawn shell '{}': {}", shell, e)))?;

        let reader = pty_pair
            .master
            .try_clone_reader()
            .map_err(|e| GhostError::Pty(format!("Failed to clone PTY reader: {}", e)))?;

        let writer = pty_pair
            .master
            .take_writer()
            .map_err(|e| GhostError::Pty(format!("Failed to take PTY writer: {}", e)))?;

        Ok(Self {
            id: Uuid::new_v4(),
            shell: shell.to_string(),
            alive: true,
            master: pty_pair.master,
            writer,
            reader: Some(reader),
            child: Some(child),
        })
    }

    /// Spawn with default dimensions (80x24)
    pub fn spawn_default(shell: &str) -> Result<Self, GhostError> {
        Self::spawn(shell, 80, 24)
    }

    /// Write data to the PTY's stdin
    pub fn write_input(&mut self, data: &[u8]) -> io::Result<()> {
        self.writer.write_all(data)?;
        self.writer.flush()?;
        Ok(())
    }

    /// Take the reader from this session (for use in a dedicated read thread/task).
    /// Returns None if the reader has already been taken.
    pub fn take_reader(&mut self) -> Option<Box<dyn Read + Send>> {
        self.reader.take()
    }

    /// Read available output from the PTY (blocking).
    /// Prefer using `take_reader()` with a dedicated thread for non-blocking reads.
    pub fn read_output_blocking(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(ref mut reader) = self.reader {
            reader.read(buf)
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "PTY reader has been taken — use the taken reader instead",
            ))
        }
    }

    /// Check if the child process is still running
    pub fn is_alive(&mut self) -> bool {
        if let Some(ref mut child) = self.child {
            match child.try_wait() {
                Ok(Some(_)) => {
                    self.alive = false;
                    false
                }
                Ok(None) => true,
                Err(_) => {
                    self.alive = false;
                    false
                }
            }
        } else {
            false
        }
    }

    /// Kill the child process
    pub fn kill(&mut self) {
        if let Some(ref mut child) = self.child {
            let _ = child.kill();
        }
        self.alive = false;
    }

    /// Resize the PTY to new dimensions.
    /// This sends SIGWINCH on Unix and resizes ConPTY on Windows.
    pub fn resize(&mut self, cols: u16, rows: u16) -> Result<(), GhostError> {
        self.master
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| GhostError::Pty(format!("Failed to resize PTY: {}", e)))
    }

    /// Get the session's UUID
    pub fn id(&self) -> Uuid {
        self.id
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        self.kill();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pty_creation() {
        let shell = if cfg!(windows) { "cmd" } else { "/bin/sh" };
        let pty = PtySession::spawn_default(shell);
        assert!(pty.is_ok(), "Failed to create PTY: {:?}", pty.err());
    }

    #[test]
    fn test_pty_is_alive() {
        let shell = if cfg!(windows) { "cmd" } else { "/bin/sh" };
        let mut pty = PtySession::spawn_default(shell).unwrap();
        assert!(pty.is_alive());
        pty.kill();
        // After kill, is_alive should return false
        assert!(!pty.is_alive());
    }

    #[test]
    fn test_pty_resize() {
        let shell = if cfg!(windows) { "cmd" } else { "/bin/sh" };
        let mut pty = PtySession::spawn_default(shell).unwrap();
        let result = pty.resize(120, 40);
        assert!(result.is_ok(), "Resize failed: {:?}", result.err());
    }

    #[test]
    fn test_pty_write_input() {
        let shell = if cfg!(windows) { "cmd" } else { "/bin/sh" };
        let mut pty = PtySession::spawn_default(shell).unwrap();
        let result = pty.write_input(b"echo hello\n");
        assert!(result.is_ok());
    }
}
