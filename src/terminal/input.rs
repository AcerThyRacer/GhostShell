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
    ExecuteCommand,
    CommandChar(char),
    CommandBackspace,
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
            InputAction::ExecuteCommand
        }
        KeyCode::Backspace => {
            InputAction::CommandBackspace
        }
        KeyCode::Char(c) => {
            InputAction::CommandChar(c)
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

/// Compute the xterm-style modifier parameter for CSI sequences.
/// xterm encodes modifiers as `1 + bitmask` where:
///   Shift=1, Alt=2, Ctrl=4  →  e.g. Shift+Ctrl = 1+(1|4) = 6
fn modifier_param(modifiers: KeyModifiers) -> Option<u8> {
    let mut bits: u8 = 0;
    if modifiers.contains(KeyModifiers::SHIFT) {
        bits |= 1;
    }
    if modifiers.contains(KeyModifiers::ALT) {
        bits |= 2;
    }
    if modifiers.contains(KeyModifiers::CONTROL) {
        bits |= 4;
    }
    if bits == 0 {
        None
    } else {
        Some(1 + bits)
    }
}

/// Build a CSI sequence with an optional modifier parameter.
/// `base` is the unmodified sequence like `\x1b[A`.
/// With modifiers it becomes `\x1b[1;{mod}A` (for letter-terminated)
/// or `\x1b[{num};{mod}~` (for tilde-terminated).
fn csi_with_modifier(base: &[u8], modifiers: KeyModifiers) -> Vec<u8> {
    if let Some(m) = modifier_param(modifiers) {
        // Determine form: tilde-terminated vs letter-terminated
        let last = *base.last().unwrap_or(&0);
        if last == b'~' {
            // e.g. \x1b[5~ → \x1b[5;{m}~
            let mut out = base[..base.len() - 1].to_vec();
            out.push(b';');
            out.extend_from_slice(m.to_string().as_bytes());
            out.push(b'~');
            out
        } else {
            // e.g. \x1b[A → \x1b[1;{m}A
            let mut out = vec![0x1b, b'[', b'1', b';'];
            out.extend_from_slice(m.to_string().as_bytes());
            out.push(last);
            out
        }
    } else {
        base.to_vec()
    }
}

/// Convert a key event to raw bytes for PTY input.
///
/// Handles all modifier combinations:
/// - **Ctrl+char**: control character (0x01–0x1a) or Ctrl+special
/// - **Alt+char**: ESC prefix (`\x1b` + char)
/// - **Shift+char**: uppercase / shifted character
/// - **Ctrl+Shift**: extended control sequences
/// - **Shift+Tab (BackTab)**: `\x1b[Z`
/// - **Modified arrows/fn/nav keys**: xterm-style `\x1b[1;{mod}X`
fn key_to_bytes(key: &KeyEvent) -> Vec<u8> {
    let mods = key.modifiers;
    let has_ctrl = mods.contains(KeyModifiers::CONTROL);
    let has_alt = mods.contains(KeyModifiers::ALT);
    let has_shift = mods.contains(KeyModifiers::SHIFT);

    match key.code {
        KeyCode::Char(c) => {
            if has_ctrl {
                // Ctrl+letter → control character (0x01–0x1A)
                let lower = c.to_ascii_lowercase();
                if lower.is_ascii_lowercase() {
                    let ctrl_byte = (lower as u8) - b'a' + 1;
                    if has_alt {
                        return vec![0x1b, ctrl_byte]; // Alt+Ctrl+letter
                    }
                    return vec![ctrl_byte];
                }
                // Ctrl+special chars
                match c {
                    '[' | '3' => return vec![0x1b],   // Ctrl+[ = ESC
                    '\\' | '4' => return vec![0x1c],  // Ctrl+\ = FS
                    ']' | '5' => return vec![0x1d],   // Ctrl+] = GS
                    '^' | '6' => return vec![0x1e],   // Ctrl+^ = RS
                    '_' | '7' => return vec![0x1f],   // Ctrl+_ = US
                    ' ' | '2' | '@' => return vec![0x00], // Ctrl+Space = NUL
                    '/' => return vec![0x1f],
                    _ => {}
                }
            }

            // Determine the character to emit
            let out_char = if has_shift && c.is_ascii_lowercase() {
                c.to_ascii_uppercase()
            } else {
                c
            };

            let mut buf = [0u8; 4];
            let s = out_char.encode_utf8(&mut buf);
            let char_bytes = s.as_bytes().to_vec();

            if has_alt {
                // Alt wraps with ESC prefix
                let mut out = vec![0x1b];
                out.extend_from_slice(&char_bytes);
                out
            } else {
                char_bytes
            }
        }

        KeyCode::Enter => vec![b'\r'],
        KeyCode::Backspace => {
            if has_alt {
                vec![0x1b, 0x7f]
            } else {
                vec![0x7f]
            }
        }
        KeyCode::Delete => csi_with_modifier(&[0x1b, b'[', b'3', b'~'], mods),
        KeyCode::Tab => {
            if has_shift {
                vec![0x1b, b'[', b'Z'] // BackTab (Shift+Tab)
            } else {
                vec![b'\t']
            }
        }
        KeyCode::BackTab => vec![0x1b, b'[', b'Z'],
        KeyCode::Esc => vec![0x1b],

        // Arrow keys with modifier support
        KeyCode::Up => csi_with_modifier(&[0x1b, b'[', b'A'], mods),
        KeyCode::Down => csi_with_modifier(&[0x1b, b'[', b'B'], mods),
        KeyCode::Right => csi_with_modifier(&[0x1b, b'[', b'C'], mods),
        KeyCode::Left => csi_with_modifier(&[0x1b, b'[', b'D'], mods),

        // Navigation keys with modifier support
        KeyCode::Home => csi_with_modifier(&[0x1b, b'[', b'H'], mods),
        KeyCode::End => csi_with_modifier(&[0x1b, b'[', b'F'], mods),
        KeyCode::PageUp => csi_with_modifier(&[0x1b, b'[', b'5', b'~'], mods),
        KeyCode::PageDown => csi_with_modifier(&[0x1b, b'[', b'6', b'~'], mods),
        KeyCode::Insert => csi_with_modifier(&[0x1b, b'[', b'2', b'~'], mods),

        // Function keys — standard xterm encoding F1-F12
        KeyCode::F(n) => {
            let base: Vec<u8> = match n {
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
                _ => return vec![],
            };
            // F1-F4 use SS3 format; with modifiers switch to CSI format
            if n <= 4 {
                if let Some(m) = modifier_param(mods) {
                    let letter = base[2]; // P/Q/R/S
                    let mut out = vec![0x1b, b'[', b'1', b';'];
                    out.extend_from_slice(m.to_string().as_bytes());
                    out.push(letter);
                    return out;
                }
            }
            csi_with_modifier(&base, mods)
        }

        _ => vec![],
    }
}

/// Sanitize raw bytes before sending to a PTY.
///
/// Strips dangerous byte patterns that could be used for terminal injection:
/// - NUL bytes (0x00) which can confuse terminals
/// - Incomplete/malformed escape sequences (stray 0x1b not followed by valid CSI)
///
/// Returns the sanitized byte vector.
pub fn sanitize_pty_bytes(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        let b = data[i];
        if b == 0x00 {
            // Skip NUL bytes — they can confuse terminal state
            i += 1;
            continue;
        }
        if b == 0x1b {
            // Validate escape sequence has at least one following byte
            if i + 1 < data.len() {
                let next = data[i + 1];
                // Valid followers: '[' (CSI), 'O' (SS3), 'P'-'_' (intermediate),
                // or 0x20-0x7E (2-char sequence like Alt+key)
                if next == b'[' || next == b'O' || (0x20..=0x7E).contains(&next) {
                    out.push(b);
                } else {
                    // Invalid follower — drop the ESC
                    i += 1;
                    continue;
                }
            } else {
                // Lone ESC at end — still valid (Escape key)
                out.push(b);
            }
        } else {
            out.push(b);
        }
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Mode transition tests ────────────────────────────────────

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
    fn test_split_vertical() {
        let mut mode = InputMode::Prefix;
        let key = KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE);
        let action = process_key(key, &mut mode);
        assert!(matches!(action, InputAction::SplitVertical));
    }

    #[test]
    fn test_panic_sequence() {
        let mut mode = InputMode::Normal;
        let ctrl_g = KeyEvent::new(KeyCode::Char('g'), KeyModifiers::CONTROL);

        let _ = process_key(ctrl_g, &mut mode);
        assert!(matches!(mode, InputMode::Prefix));

        let _ = process_key(ctrl_g, &mut mode);
        assert!(matches!(mode, InputMode::PanicSequence { count: 2 }));

        let action = process_key(ctrl_g, &mut mode);
        assert!(matches!(action, InputAction::PanicSwitch));
    }

    #[test]
    fn test_panic_sequence_broken() {
        let mut mode = InputMode::PanicSequence { count: 2 };
        let key = KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE);
        let action = process_key(key, &mut mode);
        assert!(matches!(action, InputAction::None));
        assert!(matches!(mode, InputMode::Normal));
    }

    #[test]
    fn test_passthrough() {
        let mut mode = InputMode::Normal;
        let key = KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE);
        let action = process_key(key, &mut mode);
        assert!(matches!(action, InputAction::PassThrough(_)));
    }

    #[test]
    fn test_command_mode_enter_execute() {
        let mut mode = InputMode::Prefix;
        let colon = KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE);
        let action = process_key(colon, &mut mode);
        assert!(matches!(action, InputAction::EnterCommand));
        assert!(matches!(mode, InputMode::Command));

        let enter = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
        let action = process_key(enter, &mut mode);
        assert!(matches!(action, InputAction::ExecuteCommand));
        assert!(matches!(mode, InputMode::Normal));
    }

    #[test]
    fn test_command_mode_char_backspace() {
        let mut mode = InputMode::Command;
        let a = KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE);
        let action = process_key(a, &mut mode);
        assert!(matches!(action, InputAction::CommandChar('a')));

        let bs = KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE);
        let action = process_key(bs, &mut mode);
        assert!(matches!(action, InputAction::CommandBackspace));
    }

    #[test]
    fn test_command_mode_esc() {
        let mut mode = InputMode::Command;
        let esc = KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE);
        let action = process_key(esc, &mut mode);
        assert!(matches!(action, InputAction::None));
        assert!(matches!(mode, InputMode::Normal));
    }

    #[test]
    fn test_emergency_quit() {
        let mut mode = InputMode::Normal;
        let key = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL);
        let action = process_key(key, &mut mode);
        assert!(matches!(action, InputAction::Quit));
    }

    #[test]
    fn test_prefix_quit() {
        let mut mode = InputMode::Prefix;
        let key = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);
        let action = process_key(key, &mut mode);
        assert!(matches!(action, InputAction::Quit));
    }

    #[test]
    fn test_prefix_navigation() {
        for (code, expected) in [
            (KeyCode::Up, "FocusUp"),
            (KeyCode::Down, "FocusDown"),
            (KeyCode::Left, "FocusLeft"),
            (KeyCode::Right, "FocusRight"),
            (KeyCode::Char('k'), "FocusUp"),
            (KeyCode::Char('j'), "FocusDown"),
        ] {
            let mut mode = InputMode::Prefix;
            let key = KeyEvent::new(code, KeyModifiers::NONE);
            let action = process_key(key, &mut mode);
            let action_str = format!("{:?}", action);
            assert!(action_str.contains(expected), "expected {} for {:?}", expected, code);
        }
    }

    #[test]
    fn test_prefix_tabs() {
        let mut mode = InputMode::Prefix;
        let t = KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE);
        assert!(matches!(process_key(t, &mut mode), InputAction::NewTab));

        mode = InputMode::Prefix;
        let n = KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE);
        assert!(matches!(process_key(n, &mut mode), InputAction::NextTab));

        mode = InputMode::Prefix;
        let p = KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE);
        assert!(matches!(process_key(p, &mut mode), InputAction::PrevTab));
    }

    #[test]
    fn test_prefix_record_wipe() {
        let mut mode = InputMode::Prefix;
        let r = KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE);
        assert!(matches!(process_key(r, &mut mode), InputAction::ToggleRecord));

        mode = InputMode::Prefix;
        let w = KeyEvent::new(KeyCode::Char('w'), KeyModifiers::NONE);
        assert!(matches!(process_key(w, &mut mode), InputAction::WipeScrollback));
    }

    // ── key_to_bytes tests ───────────────────────────────────────

    #[test]
    fn test_plain_chars() {
        let key = KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE);
        assert_eq!(key_to_bytes(&key), vec![b'a']);
    }

    #[test]
    fn test_ctrl_chars() {
        // Ctrl+A = 0x01, Ctrl+C = 0x03, Ctrl+Z = 0x1A
        for (c, expected) in [('a', 0x01), ('c', 0x03), ('z', 0x1a)] {
            let key = KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL);
            assert_eq!(key_to_bytes(&key), vec![expected], "Ctrl+{} failed", c);
        }
    }

    #[test]
    fn test_alt_chars() {
        let key = KeyEvent::new(KeyCode::Char('x'), KeyModifiers::ALT);
        assert_eq!(key_to_bytes(&key), vec![0x1b, b'x']);
    }

    #[test]
    fn test_alt_ctrl_chars() {
        let key = KeyEvent::new(
            KeyCode::Char('c'),
            KeyModifiers::ALT | KeyModifiers::CONTROL,
        );
        assert_eq!(key_to_bytes(&key), vec![0x1b, 0x03]); // Alt + Ctrl+C
    }

    #[test]
    fn test_shift_lowercase_becomes_uppercase() {
        let key = KeyEvent::new(KeyCode::Char('a'), KeyModifiers::SHIFT);
        assert_eq!(key_to_bytes(&key), vec![b'A']);
    }

    #[test]
    fn test_tab_and_backtab() {
        let tab = KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE);
        assert_eq!(key_to_bytes(&tab), vec![b'\t']);

        let shift_tab = KeyEvent::new(KeyCode::Tab, KeyModifiers::SHIFT);
        assert_eq!(key_to_bytes(&shift_tab), vec![0x1b, b'[', b'Z']);

        let backtab = KeyEvent::new(KeyCode::BackTab, KeyModifiers::NONE);
        assert_eq!(key_to_bytes(&backtab), vec![0x1b, b'[', b'Z']);
    }

    #[test]
    fn test_enter_backspace_delete() {
        let enter = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(key_to_bytes(&enter), vec![b'\r']);

        let bs = KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE);
        assert_eq!(key_to_bytes(&bs), vec![0x7f]);

        let alt_bs = KeyEvent::new(KeyCode::Backspace, KeyModifiers::ALT);
        assert_eq!(key_to_bytes(&alt_bs), vec![0x1b, 0x7f]);

        let del = KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE);
        assert_eq!(key_to_bytes(&del), vec![0x1b, b'[', b'3', b'~']);
    }

    #[test]
    fn test_arrow_keys_plain() {
        assert_eq!(
            key_to_bytes(&KeyEvent::new(KeyCode::Up, KeyModifiers::NONE)),
            vec![0x1b, b'[', b'A']
        );
        assert_eq!(
            key_to_bytes(&KeyEvent::new(KeyCode::Down, KeyModifiers::NONE)),
            vec![0x1b, b'[', b'B']
        );
    }

    #[test]
    fn test_arrow_keys_with_modifiers() {
        // Shift+Up → \x1b[1;2A
        let key = KeyEvent::new(KeyCode::Up, KeyModifiers::SHIFT);
        assert_eq!(key_to_bytes(&key), vec![0x1b, b'[', b'1', b';', b'2', b'A']);

        // Ctrl+Right → \x1b[1;5C
        let key = KeyEvent::new(KeyCode::Right, KeyModifiers::CONTROL);
        assert_eq!(key_to_bytes(&key), vec![0x1b, b'[', b'1', b';', b'5', b'C']);

        // Ctrl+Shift+Left → \x1b[1;6D
        let key = KeyEvent::new(
            KeyCode::Left,
            KeyModifiers::CONTROL | KeyModifiers::SHIFT,
        );
        assert_eq!(key_to_bytes(&key), vec![0x1b, b'[', b'1', b';', b'6', b'D']);
    }

    #[test]
    fn test_function_keys_plain() {
        assert_eq!(
            key_to_bytes(&KeyEvent::new(KeyCode::F(1), KeyModifiers::NONE)),
            vec![0x1b, b'O', b'P']
        );
        assert_eq!(
            key_to_bytes(&KeyEvent::new(KeyCode::F(5), KeyModifiers::NONE)),
            vec![0x1b, b'[', b'1', b'5', b'~']
        );
        assert_eq!(
            key_to_bytes(&KeyEvent::new(KeyCode::F(12), KeyModifiers::NONE)),
            vec![0x1b, b'[', b'2', b'4', b'~']
        );
    }

    #[test]
    fn test_function_keys_with_modifiers() {
        // Shift+F1 → \x1b[1;2P
        let key = KeyEvent::new(KeyCode::F(1), KeyModifiers::SHIFT);
        assert_eq!(key_to_bytes(&key), vec![0x1b, b'[', b'1', b';', b'2', b'P']);

        // Ctrl+F5 → \x1b[15;5~
        let key = KeyEvent::new(KeyCode::F(5), KeyModifiers::CONTROL);
        assert_eq!(key_to_bytes(&key), vec![0x1b, b'[', b'1', b'5', b';', b'5', b'~']);
    }

    #[test]
    fn test_nav_keys() {
        assert_eq!(
            key_to_bytes(&KeyEvent::new(KeyCode::Home, KeyModifiers::NONE)),
            vec![0x1b, b'[', b'H']
        );
        assert_eq!(
            key_to_bytes(&KeyEvent::new(KeyCode::End, KeyModifiers::NONE)),
            vec![0x1b, b'[', b'F']
        );
        assert_eq!(
            key_to_bytes(&KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE)),
            vec![0x1b, b'[', b'5', b'~']
        );
    }

    #[test]
    fn test_ctrl_special_chars() {
        // Ctrl+[ = ESC
        let key = KeyEvent::new(KeyCode::Char('['), KeyModifiers::CONTROL);
        assert_eq!(key_to_bytes(&key), vec![0x1b]);

        // Ctrl+Space = NUL
        let key = KeyEvent::new(KeyCode::Char(' '), KeyModifiers::CONTROL);
        assert_eq!(key_to_bytes(&key), vec![0x00]);
    }

    #[test]
    fn test_unicode_passthrough() {
        let key = KeyEvent::new(KeyCode::Char('é'), KeyModifiers::NONE);
        let bytes = key_to_bytes(&key);
        assert_eq!(bytes, "é".as_bytes());
    }

    #[test]
    fn test_esc_key() {
        let key = KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE);
        assert_eq!(key_to_bytes(&key), vec![0x1b]);
    }

    #[test]
    fn test_unknown_keycode_returns_empty() {
        let key = KeyEvent::new(KeyCode::Null, KeyModifiers::NONE);
        assert!(key_to_bytes(&key).is_empty());
    }

    // ── Sanitization tests ───────────────────────────────────────

    #[test]
    fn test_sanitize_strips_nul() {
        let data = vec![b'h', 0x00, b'i'];
        assert_eq!(sanitize_pty_bytes(&data), vec![b'h', b'i']);
    }

    #[test]
    fn test_sanitize_valid_escape() {
        let data = vec![0x1b, b'[', b'A']; // Up arrow
        assert_eq!(sanitize_pty_bytes(&data), data);
    }

    #[test]
    fn test_sanitize_invalid_escape_follower() {
        // ESC followed by 0x80 (invalid) — ESC dropped, 0x80 kept
        let data = vec![0x1b, 0x80, b'a'];
        // ESC dropped because 0x80 is outside 0x20-0x7E
        assert_eq!(sanitize_pty_bytes(&data), vec![0x80, b'a']);
    }

    #[test]
    fn test_sanitize_lone_esc_at_end() {
        // Lone ESC at end is valid (Esc key press)
        let data = vec![b'a', 0x1b];
        assert_eq!(sanitize_pty_bytes(&data), data);
    }

    #[test]
    fn test_sanitize_empty() {
        assert!(sanitize_pty_bytes(&[]).is_empty());
    }

    #[test]
    fn test_sanitize_alt_key() {
        let data = vec![0x1b, b'x']; // Alt+x
        assert_eq!(sanitize_pty_bytes(&data), data);
    }

    // ── modifier_param tests ─────────────────────────────────────

    #[test]
    fn test_modifier_param() {
        assert_eq!(modifier_param(KeyModifiers::NONE), None);
        assert_eq!(modifier_param(KeyModifiers::SHIFT), Some(2));
        assert_eq!(modifier_param(KeyModifiers::ALT), Some(3));
        assert_eq!(modifier_param(KeyModifiers::CONTROL), Some(5));
        assert_eq!(
            modifier_param(KeyModifiers::SHIFT | KeyModifiers::CONTROL),
            Some(6)
        );
        assert_eq!(
            modifier_param(KeyModifiers::SHIFT | KeyModifiers::ALT | KeyModifiers::CONTROL),
            Some(8)
        );
    }
}
