// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Input Handler                          ║
// ║         Modal keybinding router with prefix key support          ║
// ╚══════════════════════════════════════════════════════════════════╝

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// Input processing mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    /// Normal mode — input goes to active pane
    Normal,
    /// Prefix pressed — waiting for command key
    Prefix,
    /// Command mode — typing a command
    Command,
    /// Panic sequence in progress
    PanicSequence { count: u8 },
}

/// Actions the input handler can dispatch
#[derive(Debug, Clone)]
pub enum InputAction {
    SplitHorizontal,
    SplitVertical,
    FocusUp,
    FocusDown,
    FocusLeft,
    FocusRight,
    ClosePane,
    NewTab,
    NextTab,
    PrevTab,
    ToggleRecord,
    WipeScrollback,
    PanicSwitch,
    EnterCommand,
    Quit,
    PassThrough(Vec<u8>),
    None,
}

/// Process a key event and return the appropriate action
pub fn process_key(key: KeyEvent, mode: &mut InputMode) -> InputAction {
    let current_count = match *mode {
        InputMode::PanicSequence { count } => Some(count),
        _ => None,
    };
    match mode {
        InputMode::Normal => process_normal_key(key, mode),
        InputMode::Prefix => process_prefix_key(key, mode),
        InputMode::Command => process_command_key(key, mode),
        InputMode::PanicSequence { .. } => process_panic_key(key, mode, current_count.unwrap()),
    }
}

/// Process keys in normal mode
fn process_normal_key(key: KeyEvent, mode: &mut InputMode) -> InputAction {
    // Check for prefix key: Ctrl+G
    if key.code == KeyCode::Char('g') && key.modifiers.contains(KeyModifiers::CONTROL) {
        *mode = InputMode::Prefix;
        return InputAction::None;
    }

    // Emergency quit: Ctrl+Q
    if key.code == KeyCode::Char('q') && key.modifiers.contains(KeyModifiers::CONTROL) {
        return InputAction::Quit;
    }

    // Pass all other input to the active pane
    let data = key_to_bytes(&key);
    if !data.is_empty() {
        InputAction::PassThrough(data)
    } else {
        InputAction::None
    }
}

/// Process keys after prefix (Ctrl+G) has been pressed
fn process_prefix_key(key: KeyEvent, mode: &mut InputMode) -> InputAction {
    *mode = InputMode::Normal;

    // Check for panic sequence: Ctrl+G again (need 3 total)
    if key.code == KeyCode::Char('g') && key.modifiers.contains(KeyModifiers::CONTROL) {
        *mode = InputMode::PanicSequence { count: 2 };
        return InputAction::None;
    }

    match key.code {
        // Splits
        KeyCode::Char('h') => InputAction::SplitHorizontal,
        KeyCode::Char('v') => InputAction::SplitVertical,

        // Navigation
        KeyCode::Up => InputAction::FocusUp,
        KeyCode::Down => InputAction::FocusDown,
        KeyCode::Left => InputAction::FocusLeft,
        KeyCode::Right => InputAction::FocusRight,
        KeyCode::Char('k') => InputAction::FocusUp,
        KeyCode::Char('j') => InputAction::FocusDown,

        // Pane management
        KeyCode::Char('x') => InputAction::ClosePane,

        // Tabs
        KeyCode::Char('t') => InputAction::NewTab,
        KeyCode::Char('n') => InputAction::NextTab,
        KeyCode::Char('p') => InputAction::PrevTab,

        // Recording
        KeyCode::Char('r') => InputAction::ToggleRecord,

        // Wipe scrollback
        KeyCode::Char('w') => InputAction::WipeScrollback,

        // Command mode
        KeyCode::Char(':') => {
            *mode = InputMode::Command;
            InputAction::EnterCommand
        }

        // Quit
        KeyCode::Char('q') => InputAction::Quit,

        // Unknown prefix command — ignore
        _ => InputAction::None,
    }
}

/// Process keys in command mode
fn process_command_key(key: KeyEvent, mode: &mut InputMode) -> InputAction {
    match key.code {
        KeyCode::Esc => {
            *mode = InputMode::Normal;
            InputAction::None
        }
        KeyCode::Enter => {
            *mode = InputMode::Normal;
            // Command execution would happen here
            InputAction::None
        }
        _ => InputAction::None,
    }
}

/// Process panic key sequence (need 3x Ctrl+G)
fn process_panic_key(key: KeyEvent, mode: &mut InputMode, count: u8) -> InputAction {
    if key.code == KeyCode::Char('g') && key.modifiers.contains(KeyModifiers::CONTROL) {
        if count >= 2 {
            *mode = InputMode::Normal;
            return InputAction::PanicSwitch;
        }
        *mode = InputMode::PanicSequence { count: count + 1 };
        return InputAction::None;
    }

    // Sequence broken — return to normal
    *mode = InputMode::Normal;
    InputAction::None
}

/// Convert a key event to raw bytes for PTY input
fn key_to_bytes(key: &KeyEvent) -> Vec<u8> {
    match key.code {
        KeyCode::Char(c) => {
            if key.modifiers.contains(KeyModifiers::CONTROL) {
                // Control characters: Ctrl+A = 0x01, Ctrl+B = 0x02, etc.
                let ctrl_char = (c as u8).wrapping_sub(b'a').wrapping_add(1);
                if ctrl_char <= 26 {
                    return vec![ctrl_char];
                }
            }
            let mut buf = [0u8; 4];
            let s = c.encode_utf8(&mut buf);
            s.as_bytes().to_vec()
        }
        KeyCode::Enter => vec![b'\r'],
        KeyCode::Backspace => vec![0x7f],
        KeyCode::Delete => vec![0x1b, b'[', b'3', b'~'],
        KeyCode::Tab => vec![b'\t'],
        KeyCode::Esc => vec![0x1b],
        KeyCode::Up => vec![0x1b, b'[', b'A'],
        KeyCode::Down => vec![0x1b, b'[', b'B'],
        KeyCode::Right => vec![0x1b, b'[', b'C'],
        KeyCode::Left => vec![0x1b, b'[', b'D'],
        KeyCode::Home => vec![0x1b, b'[', b'H'],
        KeyCode::End => vec![0x1b, b'[', b'F'],
        KeyCode::PageUp => vec![0x1b, b'[', b'5', b'~'],
        KeyCode::PageDown => vec![0x1b, b'[', b'6', b'~'],
        KeyCode::Insert => vec![0x1b, b'[', b'2', b'~'],
        KeyCode::F(n) => {
            match n {
                1 => vec![0x1b, b'O', b'P'],
                2 => vec![0x1b, b'O', b'Q'],
                3 => vec![0x1b, b'O', b'R'],
                4 => vec![0x1b, b'O', b'S'],
                5 => vec![0x1b, b'[', b'1', b'5', b'~'],
                6 => vec![0x1b, b'[', b'1', b'7', b'~'],
                7 => vec![0x1b, b'[', b'1', b'8', b'~'],
                8 => vec![0x1b, b'[', b'1', b'9', b'~'],
                9 => vec![0x1b, b'[', b'2', b'0', b'~'],
                10 => vec![0x1b, b'[', b'2', b'1', b'~'],
                11 => vec![0x1b, b'[', b'2', b'3', b'~'],
                12 => vec![0x1b, b'[', b'2', b'4', b'~'],
                _ => vec![],
            }
        }
        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_key_detection() {
        let mut mode = InputMode::Normal;
        let key = KeyEvent::new(KeyCode::Char('g'), KeyModifiers::CONTROL);
        let action = process_key(key, &mut mode);
        assert!(matches!(action, InputAction::None));
        assert!(matches!(mode, InputMode::Prefix));
    }

    #[test]
    fn test_split_horizontal() {
        let mut mode = InputMode::Prefix;
        let key = KeyEvent::new(KeyCode::Char('h'), KeyModifiers::NONE);
        let action = process_key(key, &mut mode);
        assert!(matches!(action, InputAction::SplitHorizontal));
        assert!(matches!(mode, InputMode::Normal));
    }

    #[test]
    fn test_panic_sequence() {
        let mut mode = InputMode::Normal;
        let ctrl_g = KeyEvent::new(KeyCode::Char('g'), KeyModifiers::CONTROL);

        // First Ctrl+G — enters prefix
        let _ = process_key(ctrl_g, &mut mode);
        assert!(matches!(mode, InputMode::Prefix));

        // Second Ctrl+G — enters panic sequence
        let _ = process_key(ctrl_g, &mut mode);
        assert!(matches!(mode, InputMode::PanicSequence { count: 2 }));

        // Third Ctrl+G — triggers panic
        let action = process_key(ctrl_g, &mut mode);
        assert!(matches!(action, InputAction::PanicSwitch));
    }

    #[test]
    fn test_passthrough() {
        let mut mode = InputMode::Normal;
        let key = KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE);
        let action = process_key(key, &mut mode);
        assert!(matches!(action, InputAction::PassThrough(_)));
    }
}
