//! Bounded output: a tail buffer that keeps the last bytes a command wrote, and the step from raw
//! bytes to what a requester sees (valid UTF-8, redacted, within its byte limit, cut at a
//! character boundary from the start, as a byte limit on output is usually meant).

use crate::redact::redact;
use crate::sandbox::{ByteLimit, Captured, Cut};

/// A buffer that keeps the last `cap` bytes pushed to it.
#[derive(Debug, Clone)]
pub struct Tail {
    cap: usize,
    bytes: Vec<u8>,
    cut: Cut,
}

impl Tail {
    /// An empty buffer that keeps `cap` bytes.
    pub fn new(cap: ByteLimit) -> Self {
        Self {
            cap: cap.0.max(1),
            bytes: Vec::new(),
            cut: Cut::Whole,
        }
    }

    /// Appends output. Memory stays under twice the cap.
    pub fn push(&mut self, chunk: &[u8]) {
        self.bytes.extend_from_slice(chunk);
        if self.bytes.len() > self.cap * 2 {
            self.trim();
        }
    }

    fn trim(&mut self) {
        let drop = self.bytes.len().saturating_sub(self.cap);
        if drop > 0 {
            self.bytes.drain(..drop);
            self.cut = Cut::Head;
        }
    }

    /// What is kept.
    pub fn captured(&self) -> Captured {
        let over = self.bytes.len().saturating_sub(self.cap);
        Captured {
            bytes: self.bytes[over..].to_vec(),
            cut: if over > 0 { Cut::Head } else { self.cut },
        }
    }
}

/// Output as a requester sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shown {
    /// Valid UTF-8, secrets masked, at most the limit.
    pub text: String,
    /// Whether the beginning was dropped.
    pub cut: Cut,
}

/// `captured` as text within `limit` bytes.
pub fn shown(captured: &Captured, limit: ByteLimit) -> Shown {
    let text = redact(&String::from_utf8_lossy(&captured.bytes));
    let mut start = text.len().saturating_sub(limit.0);
    while !text.is_char_boundary(start) {
        start += 1;
    }
    let cut = if start > 0 { Cut::Head } else { captured.cut };
    Shown {
        text: text[start..].to_owned(),
        cut,
    }
}
