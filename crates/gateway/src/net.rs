//! Shared SMTP-over-socket plumbing for the real inbound/outbound network legs (spec §7).
//!
//! The verified bridge logic lives in [`crate::inbound`] / [`crate::outbound`] behind traits; this
//! module is *only* the thin socket layer those traits abstracted away: line framing, SMTP reply
//! parsing, and the shared rustls crypto provider. It holds no protocol policy of its own.

use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use rustls::crypto::CryptoProvider;

/// The process-wide rustls crypto provider (ring). Built explicitly per-config via
/// `*_with_provider` so we never depend on a global `install_default` having run — important in a
/// test binary where several configs are constructed concurrently.
pub(crate) fn crypto_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Read one CRLF-terminated line from `r` as **raw bytes**, returned **without** the trailing
/// CR/LF. `Ok(None)` signals a clean EOF at a line boundary (peer hung up). Reads a byte at a time
/// so we never buffer past the line — critical for STARTTLS, where the very next byte after our
/// `220` is TLS ClientHello and must not be swallowed by a read-ahead buffer.
///
/// Bytes, not `String`, on purpose (the audit's item 1): an SMTP `DATA` line is arbitrary 8-bit
/// content (ISO-8859-x, GB18030, Shift_JIS, …), and a lossy UTF-8 decode here turned every such
/// byte into U+FFFD **before DKIM verification** — corrupting stored mail and breaking body hashes.
/// The inbound MX feeds these bytes straight through; reply/command contexts that genuinely want
/// text use [`read_line_str`].
pub(crate) fn read_line(r: &mut dyn Read) -> io::Result<Option<Vec<u8>>> {
    let mut buf: Vec<u8> = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        match r.read(&mut byte) {
            Ok(0) => {
                // EOF. A clean line boundary → None; a partial line → surface as unexpected EOF.
                if buf.is_empty() {
                    return Ok(None);
                }
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed mid-line"));
            }
            Ok(_) => {
                if byte[0] == b'\n' {
                    if buf.last() == Some(&b'\r') {
                        buf.pop();
                    }
                    return Ok(Some(buf));
                }
                buf.push(byte[0]);
                // A defensive cap so a hostile peer can't force unbounded growth on one line.
                if buf.len() > 64 * 1024 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "SMTP line too long"));
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

/// [`read_line`] decoded to text for contexts that are servers' own replies / status lines (SMTP
/// reply parsing, the mesh ingest status) — ASCII per RFC 5321 §4.2, so the lossy fallback can only
/// mis-render a broken peer's reply text, never message content. DATA paths MUST use [`read_line`].
pub(crate) fn read_line_str(r: &mut dyn Read) -> io::Result<Option<String>> {
    Ok(read_line(r)?.map(|b| String::from_utf8_lossy(&b).into_owned()))
}

/// Read a (possibly multi-line) SMTP reply and return `(code, joined_text)`. Continuation lines use
/// `NNN-text`; the final line uses `NNN text` (RFC 5321 §4.2.1).
pub(crate) fn read_reply(r: &mut dyn Read) -> io::Result<(u16, String)> {
    let mut text = String::new();
    loop {
        let line = read_line_str(r)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no SMTP reply"))?;
        if line.len() < 3 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "short SMTP reply line"));
        }
        let code: u16 = line[..3]
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-numeric SMTP code"))?;
        let more = line.as_bytes().get(3) == Some(&b'-');
        if !text.is_empty() {
            text.push(' ');
        }
        text.push_str(line.get(4..).unwrap_or("").trim());
        if !more {
            return Ok((code, text));
        }
    }
}

/// Write a full string to `w` and flush.
pub(crate) fn write_all(w: &mut dyn Write, s: &str) -> io::Result<()> {
    w.write_all(s.as_bytes())?;
    w.flush()
}

/// A counting semaphore bounding how many connections one `serve_until` accept loop serves
/// concurrently (§4 in the security review — the slowloris mitigation's second half). A per-socket
/// idle timeout bounds how long any ONE connection can occupy a thread; this bounds how MANY can be
/// open at once, so an attacker cannot exhaust the whole thread/fd budget by opening many
/// connections that each merely idle inside their individual timeout window. `Clone` is cheap (an
/// `Arc<AtomicUsize>` handle) so each server can hand every accept loop the same limiter.
#[derive(Clone)]
pub(crate) struct ConnLimiter {
    active: Arc<AtomicUsize>,
    max: usize,
}

impl ConnLimiter {
    /// A limiter admitting at most `max` concurrent connections.
    pub(crate) fn new(max: usize) -> Self {
        ConnLimiter { active: Arc::new(AtomicUsize::new(0)), max }
    }

    /// Try to claim one of the `max` concurrent slots. `None` means the listener is already at
    /// capacity — the caller should refuse/close the connection rather than serve it. `Some` returns
    /// an RAII [`ConnGuard`] that releases the slot on drop (including on a panicking session thread),
    /// so a crashed connection never permanently leaks capacity.
    pub(crate) fn try_acquire(&self) -> Option<ConnGuard> {
        loop {
            let cur = self.active.load(Ordering::SeqCst);
            if cur >= self.max {
                return None;
            }
            if self.active.compare_exchange(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst).is_ok()
            {
                return Some(ConnGuard { active: self.active.clone() });
            }
        }
    }
}

/// RAII handle on one claimed [`ConnLimiter`] slot; releases it when dropped.
pub(crate) struct ConnGuard {
    active: Arc<AtomicUsize>,
}
impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Documents [`read_line`]'s exact line-termination contract, which matters for SMTP
    /// smuggling/desync analysis (the task's "bare-LF" concern): this reader treats a **bare LF**
    /// (no preceding CR) as a line terminator too, not only CRLF. RFC 5321 §2.3.7/§4.5.2 specifies
    /// CRLF as the wire line terminator and the DATA-ending sequence as `<CRLF>.<CRLF>`
    /// specifically; accepting a bare-LF-terminated line is a documented leniency (real-world
    /// MTAs commonly tolerate it), not a silent behavior. The important safety property this test
    /// pins down is that it is *consistent*: every line this gateway itself parses — commands
    /// AND `DATA` body lines — is framed by this SAME reader, so there is no second parser
    /// elsewhere in this process that could disagree with it and desync (the classic SMTP-
    /// smuggling precondition needs two disagreeing parsers in the path; this crate has one).
    #[test]
    fn read_line_terminates_on_bare_lf_as_well_as_crlf() {
        let mut r: &[u8] = b"crlf line\r\nbare-lf line\ntrailing";
        assert_eq!(read_line(&mut r).unwrap(), Some(b"crlf line".to_vec()));
        assert_eq!(read_line(&mut r).unwrap(), Some(b"bare-lf line".to_vec()));
        // No terminator at all before EOF on a non-empty remainder → UnexpectedEof, not a
        // fabricated line — a partial final line is never silently accepted as complete.
        assert!(read_line(&mut r).is_err());
    }

    #[test]
    fn read_line_a_lone_dot_terminator_is_recognized_whether_crlf_or_bare_lf() {
        // The DATA-terminator check downstream (`MxSession::feed_data`) compares a fed line
        // against the literal bytes `.` — confirm both spellings of "a lone dot line" produce the
        // identical framed line, so the terminator check cannot be evaded OR spoofed by choice of
        // line ending; both are treated identically, not one silently ignored.
        let mut a: &[u8] = b".\r\n";
        let mut b: &[u8] = b".\n";
        assert_eq!(read_line(&mut a).unwrap(), Some(b".".to_vec()));
        assert_eq!(read_line(&mut b).unwrap(), Some(b".".to_vec()));
    }

    #[test]
    fn conn_limiter_admits_up_to_max_then_refuses_until_a_slot_is_released() {
        let lim = ConnLimiter::new(2);
        let g1 = lim.try_acquire().expect("slot 1");
        let g2 = lim.try_acquire().expect("slot 2");
        assert!(lim.try_acquire().is_none(), "at capacity — a 3rd connection is refused");
        drop(g1);
        let g3 = lim.try_acquire().expect("a released slot is claimable again");
        assert!(lim.try_acquire().is_none());
        drop(g2);
        drop(g3);
        assert!(lim.try_acquire().is_some(), "fully drained back to zero");
    }
}
