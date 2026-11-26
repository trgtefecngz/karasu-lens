//! Bounded, non-blocking capture of child-process output pipes (v0.3.3+).
//!
//! Guarantees:
//! - Memory is bounded: each stream keeps at most `max_bytes` (head + tail). The tail gets the
//!   larger share because compilers and test runners print the decisive error last.
//! - Nothing is dropped silently (Constitution Art. 2): the omitted middle is replaced by an
//!   explicit `[klens] ... omitted N bytes ...` marker and reported to the caller.
//! - The pipe is always drained (the child never blocks on a full pipe), and callers can stop
//!   waiting after a grace period when a background process keeps the pipe open.

use std::io::{ErrorKind, Read};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

/// Default per-stream capture limit (16 MiB).
pub const DEFAULT_MAX_CAPTURE_BYTES: usize = 16 * 1024 * 1024;

/// Smallest accepted per-stream limit (keeps head/tail math meaningful).
const MIN_CAPTURE_BYTES: usize = 4 * 1024;

const READ_CHUNK_BYTES: usize = 64 * 1024;

/// Bytes captured from one stream plus how many bytes were omitted from its middle.
pub(crate) struct CapturedStream {
    pub bytes: Vec<u8>,
    pub omitted_bytes: u64,
}

struct BoundedBuffer {
    head: Vec<u8>,
    tail: Vec<u8>,
    total: u64,
    head_cap: usize,
    tail_cap: usize,
}

/// The per-stream limit actually enforced for a requested `max_bytes`.
pub(crate) fn effective_capture_limit(max_bytes: usize) -> usize {
    max_bytes.max(MIN_CAPTURE_BYTES)
}

impl BoundedBuffer {
    fn new(max_bytes: usize) -> Self {
        let max = effective_capture_limit(max_bytes);
        let head_cap = max / 4;
        Self {
            head: Vec::new(),
            tail: Vec::new(),
            total: 0,
            head_cap,
            tail_cap: max - head_cap,
        }
    }

    fn push(&mut self, mut chunk: &[u8]) {
        self.total = self.total.saturating_add(chunk.len() as u64);
        if self.head.len() < self.head_cap {
            let take = (self.head_cap - self.head.len()).min(chunk.len());
            self.head.extend_from_slice(&chunk[..take]);
            chunk = &chunk[take..];
        }
        if chunk.is_empty() {
            return;
        }
        self.tail.extend_from_slice(chunk);
        // Amortized trimming: only compact once the tail doubles its cap.
        if self.tail.len() > self.tail_cap.saturating_mul(2) {
            let excess = self.tail.len() - self.tail_cap;
            self.tail.drain(..excess);
        }
    }

    fn finish(mut self) -> CapturedStream {
        if self.tail.len() > self.tail_cap {
            let excess = self.tail.len() - self.tail_cap;
            self.tail.drain(..excess);
        }
        let kept = (self.head.len() + self.tail.len()) as u64;
        let omitted_bytes = self.total.saturating_sub(kept);
        let mut bytes = self.head;
        if omitted_bytes > 0 {
            bytes.extend_from_slice(
                format!(
                    "\n[klens] ... omitted {omitted_bytes} bytes of output from the middle (capture limit {} bytes; head and tail kept) ...\n",
                    self.head_cap + self.tail_cap
                )
                .as_bytes(),
            );
        }
        bytes.extend_from_slice(&self.tail);
        CapturedStream {
            bytes,
            omitted_bytes,
        }
    }
}

struct Shared {
    buffer: BoundedBuffer,
    eof: bool,
}

/// Background reader that drains one child pipe into a bounded buffer.
pub(crate) struct PipeCapture {
    shared: Arc<Mutex<Shared>>,
    max_bytes: usize,
}

fn lock(shared: &Mutex<Shared>) -> MutexGuard<'_, Shared> {
    shared.lock().unwrap_or_else(|e| e.into_inner())
}

impl PipeCapture {
    /// Start draining `reader` on a background thread (a `None` pipe is immediately at EOF).
    pub(crate) fn spawn<R: Read + Send + 'static>(reader: Option<R>, max_bytes: usize) -> Self {
        let shared = Arc::new(Mutex::new(Shared {
            buffer: BoundedBuffer::new(max_bytes),
            eof: reader.is_none(),
        }));
        if let Some(mut reader) = reader {
            let worker = Arc::clone(&shared);
            thread::spawn(move || {
                let mut chunk = vec![0u8; READ_CHUNK_BYTES];
                loop {
                    match reader.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => lock(&worker).buffer.push(&chunk[..n]),
                        Err(err) if err.kind() == ErrorKind::Interrupted => {}
                        Err(_) => break,
                    }
                }
                lock(&worker).eof = true;
            });
        }
        Self { shared, max_bytes }
    }

    fn is_eof(&self) -> bool {
        lock(&self.shared).eof
    }

    /// Take everything captured so far. If the pipe is still open (a background process holds
    /// it), the reader keeps draining into a fresh bounded buffer that is simply discarded.
    pub(crate) fn take(&self) -> CapturedStream {
        let mut guard = lock(&self.shared);
        let buffer = std::mem::replace(&mut guard.buffer, BoundedBuffer::new(self.max_bytes));
        buffer.finish()
    }
}

/// Wait until every capture reaches EOF or `grace` elapses. Returns `true` if all reached EOF.
pub(crate) fn wait_for_eof(captures: &[&PipeCapture], grace: Duration) -> bool {
    let deadline = Instant::now() + grace;
    loop {
        if captures.iter().all(|c| c.is_eof()) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_output_is_kept_verbatim() {
        let mut buf = BoundedBuffer::new(64 * 1024);
        buf.push(b"hello\n");
        buf.push(b"world\n");
        let out = buf.finish();
        assert_eq!(out.bytes, b"hello\nworld\n");
        assert_eq!(out.omitted_bytes, 0);
    }

    #[test]
    fn large_output_keeps_head_and_tail_and_marks_the_gap() {
        let max = 8 * 1024;
        let mut buf = BoundedBuffer::new(max);
        buf.push(b"HEAD_START");
        for _ in 0..1000 {
            buf.push(&[b'x'; 1000]);
        }
        buf.push(b"TAIL_END");
        let out = buf.finish();
        let text = String::from_utf8_lossy(&out.bytes);
        assert!(text.starts_with("HEAD_START"));
        assert!(text.ends_with("TAIL_END"));
        assert!(text.contains("[klens] ... omitted"));
        assert!(out.omitted_bytes > 0);
        assert!(out.bytes.len() < max + 256);
        // Exact accounting: total pushed = kept (head + tail = max) + omitted.
        let total_pushed = (10 + 1000 * 1000 + 8) as u64;
        assert_eq!(out.omitted_bytes, total_pushed - max as u64);
    }
}
