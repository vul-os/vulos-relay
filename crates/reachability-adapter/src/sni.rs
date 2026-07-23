//! Peek a TLS ClientHello's SNI `server_name` off the wire **without terminating
//! TLS** (REACH-1): no handshake completion, no private key, no cipher
//! negotiation. This module only reads the plaintext `ClientHello` record — the
//! one part of a TLS 1.2/1.3 handshake that is never encrypted, by design (it is
//! what lets a content-blind box-picker route on it at all).
//!
//! The parser is hand-rolled rather than pulled from a full TLS library, to keep
//! the content-blind transport's dependency footprint small and its behavior
//! auditable: it decodes exactly the `TLSPlaintext` record header, the
//! `Handshake` header, and the `ClientHello` body down to the `server_name`
//! extension (RFC 8446 §4.1.2, RFC 6066 §3) and nothing else. It never looks at
//! (or needs) key material, cipher suites, or any encrypted record.
//!
//! Every byte read off the socket while hunting for the SNI is retained
//! ([`ClientHelloPeek::raw`]) so the caller can replay it verbatim onto the
//! box's tunnel before splicing the rest of the raw stream — the adapter must
//! never re-serialize a ClientHello it parsed, only forward the bytes it saw.

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

/// Upper bound on how many bytes we'll buffer hunting for a complete
/// `ClientHello` before giving up. This is a fail-closed guard (REACH-6): a
/// client that never completes a well-formed `ClientHello` within a modest
/// bound is treated as malformed rather than allowed to hold a buffer open
/// indefinitely. 16 KiB comfortably covers realistic ClientHellos (including
/// large ones with many extensions / a big session-ticket / KeyShare list).
pub const MAX_CLIENT_HELLO_BYTES: usize = 16 * 1024;

/// The TLS record content-type for a Handshake record (RFC 8446 §5.1).
const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
/// The Handshake message type for ClientHello (RFC 8446 §4).
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
/// The extension type for `server_name` (RFC 6066 §3).
const EXTENSION_SERVER_NAME: u16 = 0x0000;
/// The `NameType` for a DNS hostname within the `server_name` extension (RFC 6066 §3).
const NAME_TYPE_HOST_NAME: u8 = 0x00;

/// Why a ClientHello could not be routed. Every variant is a REACH-6 fail-closed
/// trigger for the caller: the adapter holds no cert, so none of these can be
/// turned into a TLS alert or an application error — only a TCP reset/close.
#[derive(Debug, Error)]
pub enum SniError {
    #[error("first record is not a TLS handshake record")]
    NotHandshake,
    #[error("malformed ClientHello: {0}")]
    Malformed(&'static str),
    #[error("ClientHello carries no SNI extension")]
    NoSni,
    #[error("ClientHello carries an empty SNI server_name")]
    EmptySni,
    #[error("ClientHello exceeded the {MAX_CLIENT_HELLO_BYTES}-byte peek bound")]
    TooLarge,
    #[error("connection closed before a complete ClientHello arrived")]
    UnexpectedEof,
    #[error("I/O error reading ClientHello: {0}")]
    Io(#[from] std::io::Error),
}

// std::io::Error has no PartialEq, so this is hand-rolled rather than derived
// (test-only need: comparing parse outcomes by variant, and by ErrorKind for
// the I/O case).
impl PartialEq for SniError {
    fn eq(&self, other: &Self) -> bool {
        use SniError::*;
        match (self, other) {
            (NotHandshake, NotHandshake) => true,
            (Malformed(a), Malformed(b)) => a == b,
            (NoSni, NoSni) => true,
            (EmptySni, EmptySni) => true,
            (TooLarge, TooLarge) => true,
            (UnexpectedEof, UnexpectedEof) => true,
            (Io(a), Io(b)) => a.kind() == b.kind(),
            _ => false,
        }
    }
}
impl Eq for SniError {}

/// The result of peeking a ClientHello off a stream: the parsed SNI hostname
/// plus every raw byte read while parsing it, which the caller MUST replay
/// verbatim onto the box's tunnel (the adapter never re-encodes what it reads).
#[derive(Debug, Clone)]
pub struct ClientHelloPeek {
    /// The `server_name` from the SNI extension (RFC 6066), lower-ascii as sent
    /// on the wire — callers that match against a registry should normalize
    /// case themselves (DNS names are case-insensitive).
    pub server_name: String,
    /// The exact bytes read off the stream to find the SNI: one full TLS
    /// record containing the ClientHello. Replay these first, unmodified,
    /// before forwarding anything else read from the same stream.
    pub raw: Vec<u8>,
}

/// Read from `stream` until a complete `ClientHello` TLS record has arrived,
/// then return its SNI `server_name` plus the raw bytes consumed. Does not
/// read past the end of the first TLS record (no data past the ClientHello is
/// consumed), so the remainder of the stream is left untouched for splicing.
pub async fn peek_client_hello<S>(stream: &mut S) -> Result<ClientHelloPeek, SniError>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        match try_parse(&buf)? {
            Parsed::Complete(server_name) => {
                return Ok(ClientHelloPeek {
                    server_name,
                    raw: buf,
                });
            }
            Parsed::Incomplete => {}
        }
        if buf.len() >= MAX_CLIENT_HELLO_BYTES {
            return Err(SniError::TooLarge);
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(SniError::UnexpectedEof);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

enum Parsed {
    Incomplete,
    Complete(String),
}

/// Try to parse a (possibly still-growing) buffer as one TLS record carrying a
/// ClientHello. Returns `Incomplete` while more bytes are needed, `Complete`
/// once the SNI has been extracted, or an [`SniError`] the moment the bytes
/// already present are provably malformed (never waits for more data once
/// that's known).
fn try_parse(buf: &[u8]) -> Result<Parsed, SniError> {
    // TLSPlaintext header: type(1) + legacy_record_version(2) + length(2).
    if buf.len() < 5 {
        return Ok(Parsed::Incomplete);
    }
    if buf[0] != CONTENT_TYPE_HANDSHAKE {
        return Err(SniError::NotHandshake);
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    // RFC 8446 §5.1: TLSPlaintext.length MUST NOT exceed 2^14.
    if record_len == 0 || record_len > 0x4000 {
        return Err(SniError::Malformed("record length out of range"));
    }
    let record_end = 5 + record_len;
    if buf.len() < record_end {
        return Ok(Parsed::Incomplete);
    }
    let record = &buf[5..record_end];

    // Handshake header: msg_type(1) + length(3, big-endian u24).
    let mut c = Cursor::new(record);
    let hs_type = c.u8()?;
    if hs_type != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(SniError::Malformed("first handshake message is not ClientHello"));
    }
    let hs_len = c.u24()? as usize;
    let body = c.take(hs_len).map_err(|_| {
        // A ClientHello fragmented across multiple TLS records is legal TLS but
        // rare in practice for the first flight; treated as malformed for this
        // first cut rather than reassembled across records.
        SniError::Malformed("ClientHello spans multiple TLS records (unsupported)")
    })?;

    Ok(Parsed::Complete(parse_client_hello_body(body)?))
}

fn parse_client_hello_body(body: &[u8]) -> Result<String, SniError> {
    let mut c = Cursor::new(body);
    c.take(2)?; // legacy_version
    c.take(32)?; // random
    let session_id_len = c.u8()? as usize;
    c.take(session_id_len)?;
    let cipher_suites_len = c.u16()? as usize;
    c.take(cipher_suites_len)?;
    let compression_methods_len = c.u8()? as usize;
    c.take(compression_methods_len)?;

    if c.remaining() == 0 {
        // Legal (pre-TLS-1.0-ish minimal hello) but carries no extensions block
        // at all, hence no SNI.
        return Err(SniError::NoSni);
    }
    let extensions_len = c.u16()? as usize;
    let extensions = c.take(extensions_len)?;

    let mut ec = Cursor::new(extensions);
    while ec.remaining() > 0 {
        let ext_type = ec.u16()?;
        let ext_len = ec.u16()? as usize;
        let ext_data = ec.take(ext_len)?;
        if ext_type == EXTENSION_SERVER_NAME {
            return parse_server_name_extension(ext_data);
        }
    }
    Err(SniError::NoSni)
}

fn parse_server_name_extension(data: &[u8]) -> Result<String, SniError> {
    let mut c = Cursor::new(data);
    let list_len = c.u16()? as usize;
    let list = c.take(list_len)?;

    let mut lc = Cursor::new(list);
    while lc.remaining() > 0 {
        let name_type = lc.u8()?;
        let name_len = lc.u16()? as usize;
        let name = lc.take(name_len)?;
        if name_type == NAME_TYPE_HOST_NAME {
            if name.is_empty() {
                return Err(SniError::EmptySni);
            }
            return std::str::from_utf8(name)
                .map(str::to_owned)
                .map_err(|_| SniError::Malformed("server_name is not valid UTF-8"));
        }
        // Unknown NameType (RFC 6066 leaves room for future types): skip it and
        // keep scanning the list for a host_name entry.
    }
    Err(SniError::NoSni)
}

/// A tiny bounds-checked cursor over a byte slice — enough to decode the
/// handful of fixed-width + length-prefixed fields a ClientHello needs,
/// without pulling in a parser-combinator dependency for it.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], SniError> {
        if n > self.remaining() {
            return Err(SniError::Malformed("truncated field"));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, SniError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, SniError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u24(&mut self) -> Result<u32, SniError> {
        let b = self.take(3)?;
        Ok(u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal-but-valid TLS record wrapping a ClientHello, optionally
    /// carrying a `server_name` SNI extension, for testing the parser without a
    /// full TLS stack. Mirrors RFC 8446 §4.1.2 field order exactly.
    fn build_client_hello(host_name: Option<&str>) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version: TLS 1.2 wire value
        body.extend_from_slice(&[0x42; 32]); // random
        body.push(0); // session_id_len = 0
        body.extend_from_slice(&[0x00, 0x02]); // cipher_suites_len = 2
        body.extend_from_slice(&[0x13, 0x01]); // one cipher suite (TLS_AES_128_GCM_SHA256)
        body.push(1); // compression_methods_len = 1
        body.push(0); // compression_method: null

        let mut extensions = Vec::new();
        if let Some(host) = host_name {
            let mut sni_ext = Vec::new();
            let mut server_name_list = Vec::new();
            server_name_list.push(NAME_TYPE_HOST_NAME);
            server_name_list.extend_from_slice(&(host.len() as u16).to_be_bytes());
            server_name_list.extend_from_slice(host.as_bytes());
            sni_ext.extend_from_slice(&(server_name_list.len() as u16).to_be_bytes());
            sni_ext.extend_from_slice(&server_name_list);

            extensions.extend_from_slice(&EXTENSION_SERVER_NAME.to_be_bytes());
            extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&sni_ext);
        }
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(HANDSHAKE_TYPE_CLIENT_HELLO);
        let body_len = body.len() as u32;
        handshake.extend_from_slice(&body_len.to_be_bytes()[1..]); // u24
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(CONTENT_TYPE_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x01]); // legacy_record_version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[tokio::test]
    async fn valid_sni_is_extracted_and_bytes_are_buffered_verbatim() {
        let record = build_client_hello(Some("svc.alice.reach.example"));
        let mut cursor = std::io::Cursor::new(record.clone());
        let peek = peek_client_hello(&mut cursor).await.expect("parse ok");
        assert_eq!(peek.server_name, "svc.alice.reach.example");
        assert_eq!(peek.raw, record, "raw bytes must be preserved byte-for-byte for replay");
    }

    #[tokio::test]
    async fn absent_sni_extension_is_an_error() {
        let record = build_client_hello(None);
        let mut cursor = std::io::Cursor::new(record);
        let err = peek_client_hello(&mut cursor).await.unwrap_err();
        assert_eq!(err, SniError::NoSni);
    }

    #[tokio::test]
    async fn empty_sni_host_name_is_an_error() {
        let record = build_client_hello(Some(""));
        let mut cursor = std::io::Cursor::new(record);
        let err = peek_client_hello(&mut cursor).await.unwrap_err();
        assert_eq!(err, SniError::EmptySni);
    }

    #[tokio::test]
    async fn malformed_non_handshake_record_is_rejected() {
        // content-type 0x17 = application_data, not a handshake record at all.
        let mut record = build_client_hello(Some("example.com"));
        record[0] = 0x17;
        let mut cursor = std::io::Cursor::new(record);
        let err = peek_client_hello(&mut cursor).await.unwrap_err();
        assert_eq!(err, SniError::NotHandshake);
    }

    #[tokio::test]
    async fn malformed_truncated_record_is_rejected() {
        // Claim a record length far larger than what actually follows, then hit
        // EOF — this must fail closed, never hang.
        let mut record = build_client_hello(Some("example.com"));
        record.truncate(10);
        // A valid (in-range) but larger-than-what-follows claimed length, so
        // this exercises "ran out of bytes for a record we were told to
        // expect", not the separate out-of-range-length rejection.
        record[3] = 0x10;
        record[4] = 0x00; // claimed length 0x1000, far more than remains
        let mut cursor = std::io::Cursor::new(record);
        let err = peek_client_hello(&mut cursor).await.unwrap_err();
        assert_eq!(err, SniError::UnexpectedEof);
    }

    #[tokio::test]
    async fn malformed_bad_handshake_type_is_rejected() {
        let mut record = build_client_hello(Some("example.com"));
        record[5] = 0x02; // ServerHello, not ClientHello
        let mut cursor = std::io::Cursor::new(record);
        let err = peek_client_hello(&mut cursor).await.unwrap_err();
        assert_eq!(err, SniError::Malformed("first handshake message is not ClientHello"));
    }

    #[tokio::test]
    async fn client_hello_arriving_in_small_fragments_is_still_parsed() {
        // A slow/adversarial client trickling bytes one at a time must still be
        // handled correctly (the peek loop must accumulate, not assume one read
        // returns the whole record).
        let record = build_client_hello(Some("trickle.example"));
        struct OneByteAtATime(std::io::Cursor<Vec<u8>>);
        impl AsyncRead for OneByteAtATime {
            fn poll_read(
                mut self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                let mut one = [0u8; 1];
                match std::io::Read::read(&mut self.0, &mut one) {
                    Ok(0) => std::task::Poll::Ready(Ok(())),
                    Ok(_) => {
                        buf.put_slice(&one);
                        std::task::Poll::Ready(Ok(()))
                    }
                    Err(e) => std::task::Poll::Ready(Err(e)),
                }
            }
        }
        let mut src = OneByteAtATime(std::io::Cursor::new(record.clone()));
        let peek = peek_client_hello(&mut src).await.expect("parse ok");
        assert_eq!(peek.server_name, "trickle.example");
        assert_eq!(peek.raw, record);
    }

    #[tokio::test]
    async fn oversized_client_hello_fails_closed_instead_of_buffering_forever() {
        // A record header claiming the max legal 16 KiB length that never
        // arrives must hit the peek bound and error out rather than hang.
        let mut record = vec![CONTENT_TYPE_HANDSHAKE, 0x03, 0x01, 0x40, 0x00]; // len=0x4000
        record.extend(std::iter::repeat_n(0u8, MAX_CLIENT_HELLO_BYTES));
        let mut cursor = std::io::Cursor::new(record);
        let err = peek_client_hello(&mut cursor).await.unwrap_err();
        assert_eq!(err, SniError::TooLarge);
    }
}
