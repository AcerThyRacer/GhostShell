// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Session Playback Engine                ║
// ║         Speed control, seeking, HMAC integrity, .cast export    ║
// ╚══════════════════════════════════════════════════════════════════╝

use crate::crypto::session_recorder::{EventType, RecordingEvent, RecordingHeader};
use crate::error::GhostError;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io::Write;
use std::time::Duration;

type HmacSha256 = Hmac<Sha256>;

// ── Playback State ───────────────────────────────────────────────

/// State of the playback engine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaybackState {
    /// Currently replaying events
    Playing,
    /// Paused at a specific event
    Paused,
    /// Seeking to a position
    Seeking,
    /// Reached end of recording
    Finished,
    /// Not started yet
    Idle,
}

/// Playback speed multiplier
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PlaybackSpeed {
    Quarter,   // 0.25x
    Half,      // 0.5x
    Normal,    // 1.0x
    Double,    // 2.0x
    Quadruple, // 4.0x
}

impl PlaybackSpeed {
    pub fn multiplier(&self) -> f64 {
        match self {
            Self::Quarter => 0.25,
            Self::Half => 0.5,
            Self::Normal => 1.0,
            Self::Double => 2.0,
            Self::Quadruple => 4.0,
        }
    }

    /// Cycle to the next speed
    pub fn next(&self) -> Self {
        match self {
            Self::Quarter => Self::Half,
            Self::Half => Self::Normal,
            Self::Normal => Self::Double,
            Self::Double => Self::Quadruple,
            Self::Quadruple => Self::Quarter,
        }
    }

    /// Get delay adjusted for speed
    pub fn adjust_delay(&self, original: Duration) -> Duration {
        let micros = original.as_micros() as f64 / self.multiplier();
        Duration::from_micros(micros as u64)
    }
}

// ── Recording Integrity ──────────────────────────────────────────

/// HMAC-SHA256 integrity verification for recordings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingIntegrity {
    /// HMAC-SHA256 over all event data
    pub hmac: Vec<u8>,
    /// Total number of events
    pub event_count: usize,
    /// Total bytes of event data
    pub total_bytes: usize,
}

impl RecordingIntegrity {
    /// Compute integrity over a set of events
    pub fn compute(events: &[RecordingEvent], key: &[u8]) -> Self {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key error");
        let mut total_bytes = 0usize;

        for event in events {
            // Hash the event type as u8
            mac.update(&[event.event_type as u8]);
            // Hash the timestamp
            mac.update(&event.timestamp_us.to_le_bytes());
            // Hash the data length and data
            let data_len = event.data.len() as u32;
            mac.update(&data_len.to_le_bytes());
            mac.update(&event.data);
            total_bytes += event.data.len();
        }

        let result = mac.finalize();

        Self {
            hmac: result.into_bytes().to_vec(),
            event_count: events.len(),
            total_bytes,
        }
    }

    /// Verify integrity of events against stored HMAC
    pub fn verify(&self, events: &[RecordingEvent], key: &[u8]) -> bool {
        let computed = Self::compute(events, key);
        // Constant-time comparison
        if computed.hmac.len() != self.hmac.len() {
            return false;
        }
        let mut diff = 0u8;
        for (a, b) in computed.hmac.iter().zip(self.hmac.iter()) {
            diff |= a ^ b;
        }
        diff == 0 && computed.event_count == self.event_count
    }
}

// ── Playback Engine ──────────────────────────────────────────────

/// Full session playback engine with speed control, seeking, and markers
pub struct PlaybackEngine {
    /// All events in the recording
    events: Vec<RecordingEvent>,
    /// Current position in the event stream
    position: usize,
    /// Current playback state
    state: PlaybackState,
    /// Current speed
    speed: PlaybackSpeed,
    /// Header metadata
    header: RecordingHeader,
    /// Marker positions (event indices)
    markers: Vec<(usize, String)>,
}

impl PlaybackEngine {
    /// Create a new playback engine from recorded events
    pub fn new(header: RecordingHeader, events: Vec<RecordingEvent>) -> Self {
        // Extract markers
        let markers: Vec<(usize, String)> = events
            .iter()
            .enumerate()
            .filter(|(_, e)| matches!(e.event_type, EventType::Marker))
            .map(|(i, e)| (i, String::from_utf8_lossy(&e.data).to_string()))
            .collect();

        Self {
            events,
            position: 0,
            state: PlaybackState::Idle,
            speed: PlaybackSpeed::Normal,
            header,
            markers,
        }
    }

    /// Start or resume playback
    pub fn play(&mut self) {
        if self.position >= self.events.len() {
            self.state = PlaybackState::Finished;
        } else {
            self.state = PlaybackState::Playing;
        }
    }

    /// Pause playback
    pub fn pause(&mut self) {
        if self.state == PlaybackState::Playing {
            self.state = PlaybackState::Paused;
        }
    }

    /// Toggle play/pause
    pub fn toggle(&mut self) {
        match self.state {
            PlaybackState::Playing => self.pause(),
            PlaybackState::Paused | PlaybackState::Idle => self.play(),
            _ => {}
        }
    }

    /// Get the next event to replay, respecting speed
    pub fn next_event(&mut self) -> Option<(RecordingEvent, Duration)> {
        if self.state != PlaybackState::Playing {
            return None;
        }

        if self.position >= self.events.len() {
            self.state = PlaybackState::Finished;
            return None;
        }

        let event = self.events[self.position].clone();
        let delay = if self.position > 0 {
            let prev = &self.events[self.position - 1];
            let delta_us = event.timestamp_us.saturating_sub(prev.timestamp_us);
            self.speed.adjust_delay(Duration::from_micros(delta_us))
        } else {
            Duration::ZERO
        };

        self.position += 1;
        Some((event, delay))
    }

    /// Seek to a specific event position
    pub fn seek_to(&mut self, position: usize) {
        self.position = position.min(self.events.len());
        if self.position >= self.events.len() {
            self.state = PlaybackState::Finished;
        }
    }

    /// Seek to a specific timestamp (microseconds)
    pub fn seek_to_time(&mut self, target_us: u64) {
        self.state = PlaybackState::Seeking;
        let pos = self
            .events
            .iter()
            .position(|e| e.timestamp_us >= target_us)
            .unwrap_or(self.events.len());
        self.seek_to(pos);
        self.state = PlaybackState::Paused;
    }

    /// Jump to the next marker
    pub fn next_marker(&mut self) -> Option<String> {
        let next = self
            .markers
            .iter()
            .find(|(idx, _)| *idx > self.position)
            .cloned();
        if let Some((idx, label)) = next {
            self.seek_to(idx);
            Some(label)
        } else {
            None
        }
    }

    /// Jump to the previous marker
    pub fn prev_marker(&mut self) -> Option<String> {
        let prev = self
            .markers
            .iter()
            .rev()
            .find(|(idx, _)| *idx < self.position)
            .cloned();
        if let Some((idx, label)) = prev {
            self.seek_to(idx);
            Some(label)
        } else {
            None
        }
    }

    /// Set playback speed
    pub fn set_speed(&mut self, speed: PlaybackSpeed) {
        self.speed = speed;
    }

    /// Cycle to next speed
    pub fn cycle_speed(&mut self) {
        self.speed = self.speed.next();
    }

    /// Get current state
    pub fn state(&self) -> PlaybackState {
        self.state
    }

    /// Get current speed
    pub fn speed(&self) -> PlaybackSpeed {
        self.speed
    }

    /// Get current position
    pub fn position(&self) -> usize {
        self.position
    }

    /// Get total number of events
    pub fn total_events(&self) -> usize {
        self.events.len()
    }

    /// Get progress as percentage (0.0 to 1.0)
    pub fn progress(&self) -> f64 {
        if self.events.is_empty() {
            return 0.0;
        }
        self.position as f64 / self.events.len() as f64
    }

    /// Get markers
    pub fn markers(&self) -> &[(usize, String)] {
        &self.markers
    }

    /// Get header
    pub fn header(&self) -> &RecordingHeader {
        &self.header
    }

    /// Get total duration in microseconds
    pub fn total_duration_us(&self) -> u64 {
        self.events.last().map_or(0, |e| e.timestamp_us)
    }

    /// Get current timestamp position in microseconds
    pub fn current_time_us(&self) -> u64 {
        if self.position == 0 || self.events.is_empty() {
            return 0;
        }
        let idx = (self.position - 1).min(self.events.len() - 1);
        self.events[idx].timestamp_us
    }

    /// Collect all output events up to current position (to rebuild screen state)
    pub fn collect_output_to_position(&self) -> Vec<u8> {
        let mut output = Vec::new();
        for event in self.events.iter().take(self.position) {
            if matches!(event.event_type, EventType::Output) {
                output.extend_from_slice(&event.data);
            }
        }
        output
    }

    /// Export the recording as asciinema v2 .cast format (JSON Lines)
    pub fn export_asciinema(&self, writer: &mut dyn Write) -> Result<(), GhostError> {
        // Header line
        let header_json = serde_json::json!({
            "version": 2,
            "width": self.header.cols,
            "height": self.header.rows,
            "timestamp": null,
            "title": format!("GhostShell Recording {}", self.header.session_id),
            "env": {
                "SHELL": &self.header.shell,
                "TERM": "xterm-256color"
            }
        });

        writeln!(writer, "{}", header_json)
            .map_err(|e| GhostError::Io(e))?;

        // Event lines: [time_seconds, event_type, data_string]
        for event in &self.events {
            let time_secs = event.timestamp_us as f64 / 1_000_000.0;
            let event_type = if matches!(event.event_type, EventType::Input) {
                "i"
            } else {
                "o"
            };
            let data_str = String::from_utf8_lossy(&event.data);

            let line = serde_json::json!([time_secs, event_type, data_str]);
            writeln!(writer, "{}", line)
                .map_err(|e| GhostError::Io(e))?;
        }

        Ok(())
    }
}

// ── Compression helpers ──────────────────────────────────────────

/// Compress data with zstd
pub fn compress_data(data: &[u8]) -> Result<Vec<u8>, GhostError> {
    zstd::encode_all(std::io::Cursor::new(data), 3)
        .map_err(|e| GhostError::Crypto(format!("zstd compress failed: {}", e)))
}

/// Decompress zstd data
pub fn decompress_data(data: &[u8]) -> Result<Vec<u8>, GhostError> {
    zstd::decode_all(std::io::Cursor::new(data))
        .map_err(|e| GhostError::Crypto(format!("zstd decompress failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header() -> RecordingHeader {
        RecordingHeader {
            magic: *b"GHOST\x00\x01\x00",
            session_id: "test-session-id".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            cols: 80,
            rows: 24,
            shell: "bash".to_string(),
            salt: vec![0u8; 32],
            argon2_memory_kib: 65536,
            argon2_iterations: 3,
            argon2_parallelism: 4,
        }
    }

    fn make_events() -> Vec<RecordingEvent> {
        vec![
            RecordingEvent {
                event_type: EventType::Output,
                timestamp_us: 0,
                data: b"$ ".to_vec(),
            },
            RecordingEvent {
                event_type: EventType::Input,
                timestamp_us: 500_000, // 0.5s
                data: b"ls\n".to_vec(),
            },
            RecordingEvent {
                event_type: EventType::Output,
                timestamp_us: 600_000,
                data: b"file1.txt  file2.txt\n".to_vec(),
            },
            RecordingEvent {
                event_type: EventType::Marker,
                timestamp_us: 700_000,
                data: b"checkpoint-1".to_vec(),
            },
            RecordingEvent {
                event_type: EventType::Output,
                timestamp_us: 1_000_000,
                data: b"$ ".to_vec(),
            },
            RecordingEvent {
                event_type: EventType::Marker,
                timestamp_us: 1_500_000,
                data: b"checkpoint-2".to_vec(),
            },
        ]
    }

    #[test]
    fn test_playback_basic() {
        let header = make_header();
        let events = make_events();
        let mut engine = PlaybackEngine::new(header, events);

        assert_eq!(engine.state(), PlaybackState::Idle);
        assert_eq!(engine.total_events(), 6);
        assert_eq!(engine.position(), 0);

        engine.play();
        assert_eq!(engine.state(), PlaybackState::Playing);

        // First event
        let (event, delay) = engine.next_event().unwrap();
        assert!(matches!(event.event_type, EventType::Output));
        assert_eq!(delay, Duration::ZERO); // first event has no delay
        assert_eq!(engine.position(), 1);

        // Second event
        let (event, delay) = engine.next_event().unwrap();
        assert!(matches!(event.event_type, EventType::Input));
        assert_eq!(delay, Duration::from_micros(500_000));
    }

    #[test]
    fn test_playback_speed() {
        let header = make_header();
        let events = make_events();
        let mut engine = PlaybackEngine::new(header, events);
        engine.set_speed(PlaybackSpeed::Double);
        engine.play();

        let _ = engine.next_event(); // first (no delay)
        let (_, delay) = engine.next_event().unwrap();
        // 500_000us at 2x = 250_000us
        assert_eq!(delay, Duration::from_micros(250_000));
    }

    #[test]
    fn test_playback_seek() {
        let header = make_header();
        let events = make_events();
        let mut engine = PlaybackEngine::new(header, events);

        engine.seek_to(3);
        assert_eq!(engine.position(), 3);

        engine.seek_to_time(700_000);
        assert_eq!(engine.position(), 3); // marker at 700_000us
    }

    #[test]
    fn test_playback_markers() {
        let header = make_header();
        let events = make_events();
        let mut engine = PlaybackEngine::new(header, events);

        assert_eq!(engine.markers().len(), 2);

        let label = engine.next_marker().unwrap();
        assert_eq!(label, "checkpoint-1");
        assert_eq!(engine.position(), 3);

        let label = engine.next_marker().unwrap();
        assert_eq!(label, "checkpoint-2");
    }

    #[test]
    fn test_recording_integrity() {
        let events = make_events();
        let key = b"integrity-test-key-32-bytes!!!!!";

        let integrity = RecordingIntegrity::compute(&events, key);
        assert!(integrity.verify(&events, key));
        assert_eq!(integrity.event_count, 6);

        // Tamper with an event
        let mut tampered = events.clone();
        tampered[0].data = b"TAMPERED".to_vec();
        assert!(!integrity.verify(&tampered, key));
    }

    #[test]
    fn test_asciinema_export() {
        let header = make_header();
        let events = make_events();
        let engine = PlaybackEngine::new(header, events);

        let mut output = Vec::new();
        engine.export_asciinema(&mut output).unwrap();

        let text = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = text.lines().collect();

        // First line is header
        assert!(lines[0].contains("\"version\":2"));
        // Remaining lines are events
        assert!(lines.len() > 1);
    }

    #[test]
    fn test_compression_roundtrip() {
        let data = b"hello world this is some test data for compression testing";
        let compressed = compress_data(data).unwrap();
        let decompressed = decompress_data(&compressed).unwrap();
        assert_eq!(&decompressed, data);
    }

    #[test]
    fn test_playback_progress() {
        let header = make_header();
        let events = make_events();
        let mut engine = PlaybackEngine::new(header, events);

        assert_eq!(engine.progress(), 0.0);
        engine.seek_to(3);
        assert!((engine.progress() - 0.5).abs() < 0.01);
        engine.seek_to(6);
        assert!((engine.progress() - 1.0).abs() < 0.01);
    }
}
