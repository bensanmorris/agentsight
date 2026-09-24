// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

//! HTTP/1.x message framing across SSL events of one TLS connection.
//!
//! SSL_write/SSL_read calls don't line up with HTTP messages: a request body
//! can span several 16 KB writes, and a streamed (chunked) response arrives as
//! many reads, interleaved with other connections on the same thread. When
//! sslsniff reports the connection (`conn_id`), this tracker buffers each
//! connection and direction separately and hands back complete messages, with
//! chunked bodies already decoded.

use crate::event::Event;
use std::collections::{HashMap, HashSet, VecDeque};

/// Largest body kept per message; bigger messages are dropped whole rather
/// than emitted truncated.
pub(super) const MAX_HTTP1_MESSAGE_BYTES: usize = 32 * 1024 * 1024;
const MAX_HTTP1_HEAD_BYTES: usize = 64 * 1024;
const MAX_HTTP1_STREAMS: usize = 1024;

const METHODS: [&[u8]; 9] = [
    b"GET ",
    b"POST ",
    b"PUT ",
    b"PATCH ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"CONNECT ",
    b"TRACE ",
];

/// (pid, conn_id, rw) – one byte stream per connection and direction.
type StreamKey = (u32, u64, u8);

pub(super) struct Http1Message {
    /// Start line and headers, without the terminating blank line.
    pub head: Vec<u8>,
    /// Body with any chunked transfer encoding removed (still content-encoded).
    pub body: Vec<u8>,
    /// Event that carried the start of the message.
    pub first_event: Event,
    /// Timestamp of the event that completed the message.
    pub last_timestamp: u64,
    pub was_chunked: bool,
    pub is_request: bool,
}

pub(super) enum Feed {
    /// Not (or no longer) HTTP/1.x framing on this connection: use the
    /// stateless/HTTP2/WebSocket paths for this event.
    NotHttp1,
    /// Bytes were consumed; zero or more messages completed.
    Consumed(Vec<Http1Message>),
}

enum Phase {
    Head,
    Fixed(usize),
    ChunkSize,
    ChunkData(usize),
    ChunkDataEnd,
    Trailers,
}

struct Stream {
    buf: Vec<u8>,
    phase: Phase,
    head: Vec<u8>,
    body: Vec<u8>,
    chunked: bool,
    is_request: bool,
    first_event: Option<Event>,
    last_seen: u64,
}

impl Stream {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            phase: Phase::Head,
            head: Vec::new(),
            body: Vec::new(),
            chunked: false,
            is_request: false,
            first_event: None,
            last_seen: 0,
        }
    }

    fn idle(&self) -> bool {
        matches!(self.phase, Phase::Head) && self.buf.is_empty()
    }

    fn reset(&mut self) {
        *self = Self {
            last_seen: self.last_seen,
            ..Self::new()
        };
    }
}

#[derive(Default)]
pub(super) struct Http1Tracker {
    streams: HashMap<StreamKey, Stream>,
    /// Per connection: for each request sent, whether it was HEAD (its
    /// response has no body even with a Content-Length).
    head_requests: HashMap<(u32, u64), VecDeque<bool>>,
    /// Connections switched to another protocol (101), e.g. WebSocket.
    upgraded: HashSet<(u32, u64)>,
}

pub(super) fn starts_like_http1(bytes: &[u8]) -> bool {
    if bytes.starts_with(b"HTTP/1.") {
        return true;
    }
    let Some(method) = METHODS.iter().find(|m| bytes.starts_with(m)) else {
        return false;
    };
    // The request line must end in HTTP/1.x (this also rules out HTTP/2's
    // "PRI * HTTP/2.0" preface, which isn't a listed method anyway).
    let line_end = find(bytes, b"\r\n").unwrap_or(bytes.len());
    let line = &bytes[method.len()..line_end];
    line_end == bytes.len() || line.windows(7).any(|w| w == b"HTTP/1.")
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn header_value<'a>(head: &'a [u8], name: &str) -> Option<&'a [u8]> {
    head.split(|&b| b == b'\n').skip(1).find_map(|line| {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let colon = line.iter().position(|&b| b == b':')?;
        line[..colon]
            .eq_ignore_ascii_case(name.as_bytes())
            .then(|| trim(&line[colon + 1..]))
    })
}

fn trim(mut s: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = s {
        s = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = s {
        s = rest;
    }
    s
}

fn status_code(head: &[u8]) -> Option<u16> {
    let line_end = find(head, b"\r\n").unwrap_or(head.len());
    let mut parts = head[..line_end].split(|&b| b == b' ');
    parts.next()?;
    std::str::from_utf8(parts.next()?).ok()?.parse().ok()
}

impl Http1Tracker {
    pub(super) fn feed(&mut self, event: &Event, conn_id: u64, rw: u8, bytes: &[u8]) -> Feed {
        let conn = (event.pid, conn_id);
        if self.upgraded.contains(&conn) {
            return Feed::NotHttp1;
        }
        let key = (event.pid, conn_id, rw);
        let starts_message = starts_like_http1(bytes);
        let stream_idle = self.streams.get(&key).is_none_or(Stream::idle);
        if stream_idle && !starts_message {
            // Mid-stream attach, or a protocol we don't frame here.
            return Feed::NotHttp1;
        }

        self.evict_if_full(key);
        let stream = self.streams.entry(key).or_insert_with(Stream::new);
        stream.last_seen = event.timestamp;
        if stream.first_event.is_none() {
            stream.first_event = Some(event.clone());
        }
        if stream.buf.len() + bytes.len() > MAX_HTTP1_MESSAGE_BYTES + MAX_HTTP1_HEAD_BYTES {
            stream.reset();
            return Feed::Consumed(Vec::new());
        }
        stream.buf.extend_from_slice(bytes);

        let mut done = Vec::new();
        loop {
            match Self::step(stream, &mut self.head_requests, conn) {
                Step::NeedMore => break,
                Step::Error => {
                    stream.reset();
                    break;
                }
                Step::Complete => {
                    let first_event = stream
                        .first_event
                        .take()
                        .unwrap_or_else(|| event.clone());
                    let msg = Http1Message {
                        head: std::mem::take(&mut stream.head),
                        body: std::mem::take(&mut stream.body),
                        first_event,
                        last_timestamp: event.timestamp,
                        was_chunked: stream.chunked,
                        is_request: stream.is_request,
                    };
                    stream.phase = Phase::Head;
                    stream.chunked = false;
                    if !msg.is_request && status_code(&msg.head) == Some(101) {
                        self.upgraded.insert(conn);
                    }
                    done.push(msg);
                    if stream.buf.is_empty() {
                        break;
                    }
                    // A pipelined message starts in this same event.
                    stream.first_event = Some(event.clone());
                }
            }
        }
        if self.upgraded.contains(&conn) {
            self.streams.retain(|k, _| (k.0, k.1) != conn);
        }
        Feed::Consumed(done)
    }

    fn step(
        stream: &mut Stream,
        head_requests: &mut HashMap<(u32, u64), VecDeque<bool>>,
        conn: (u32, u64),
    ) -> Step {
        match stream.phase {
            Phase::Head => {
                let Some(end) = find(&stream.buf, b"\r\n\r\n") else {
                    return if stream.buf.len() > MAX_HTTP1_HEAD_BYTES {
                        Step::Error
                    } else {
                        Step::NeedMore
                    };
                };
                if !starts_like_http1(&stream.buf) {
                    return Step::Error;
                }
                stream.head = stream.buf.drain(..end + 4).take(end).collect();
                stream.is_request = !stream.head.starts_with(b"HTTP/");
                let head = &stream.head;
                let chunked = header_value(head, "transfer-encoding")
                    .is_some_and(|v| v.to_ascii_lowercase().windows(7).any(|w| w == b"chunked"));
                let content_length = header_value(head, "content-length")
                    .and_then(|v| std::str::from_utf8(v).ok()?.parse::<usize>().ok());
                if stream.is_request {
                    head_requests
                        .entry(conn)
                        .or_default()
                        .push_back(head.starts_with(b"HEAD "));
                    if chunked {
                        stream.chunked = true;
                        stream.phase = Phase::ChunkSize;
                    } else {
                        match content_length {
                            Some(n) if n > 0 => stream.phase = Phase::Fixed(n),
                            _ => return Step::Complete,
                        }
                    }
                } else {
                    let was_head = head_requests
                        .get_mut(&conn)
                        .and_then(VecDeque::pop_front)
                        .unwrap_or(false);
                    let status = status_code(head).unwrap_or(200);
                    if was_head || (100..200).contains(&status) || status == 204 || status == 304 {
                        return Step::Complete;
                    }
                    if chunked {
                        stream.chunked = true;
                        stream.phase = Phase::ChunkSize;
                    } else {
                        match content_length {
                            Some(0) => return Step::Complete,
                            Some(n) => stream.phase = Phase::Fixed(n),
                            // Delimited by connection close, which isn't observed:
                            // keep what arrived with the head.
                            None => {
                                stream.body = std::mem::take(&mut stream.buf);
                                return Step::Complete;
                            }
                        }
                    }
                }
                if stream.buf.is_empty() {
                    Step::NeedMore
                } else {
                    Self::step(stream, head_requests, conn)
                }
            }
            Phase::Fixed(remaining) => {
                let take = remaining.min(stream.buf.len());
                stream.body.extend(stream.buf.drain(..take));
                if take == remaining {
                    Step::Complete
                } else {
                    stream.phase = Phase::Fixed(remaining - take);
                    Step::NeedMore
                }
            }
            Phase::ChunkSize => {
                let Some(nl) = find(&stream.buf, b"\r\n") else {
                    return if stream.buf.len() > 1024 { Step::Error } else { Step::NeedMore };
                };
                let line: Vec<u8> = stream.buf.drain(..nl + 2).take(nl).collect();
                let size_hex = line.split(|&b| b == b';').next().unwrap_or_default();
                let Some(size) = std::str::from_utf8(trim(size_hex))
                    .ok()
                    .and_then(|s| usize::from_str_radix(s, 16).ok())
                else {
                    return Step::Error;
                };
                if stream.body.len() + size > MAX_HTTP1_MESSAGE_BYTES {
                    return Step::Error;
                }
                stream.phase = if size == 0 { Phase::Trailers } else { Phase::ChunkData(size) };
                Self::step(stream, head_requests, conn)
            }
            Phase::ChunkData(remaining) => {
                let take = remaining.min(stream.buf.len());
                stream.body.extend(stream.buf.drain(..take));
                if take == remaining {
                    stream.phase = Phase::ChunkDataEnd;
                    Self::step(stream, head_requests, conn)
                } else {
                    stream.phase = Phase::ChunkData(remaining - take);
                    Step::NeedMore
                }
            }
            Phase::ChunkDataEnd => {
                if stream.buf.len() < 2 {
                    return Step::NeedMore;
                }
                if &stream.buf[..2] != b"\r\n" {
                    return Step::Error;
                }
                stream.buf.drain(..2);
                stream.phase = Phase::ChunkSize;
                Self::step(stream, head_requests, conn)
            }
            Phase::Trailers => {
                if stream.buf.starts_with(b"\r\n") {
                    stream.buf.drain(..2);
                    return Step::Complete;
                }
                match find(&stream.buf, b"\r\n\r\n") {
                    Some(end) => {
                        stream.buf.drain(..end + 4);
                        Step::Complete
                    }
                    None => Step::NeedMore,
                }
            }
        }
    }

    fn evict_if_full(&mut self, keep: StreamKey) {
        if self.streams.len() < MAX_HTTP1_STREAMS || self.streams.contains_key(&keep) {
            return;
        }
        if let Some(oldest) = self
            .streams
            .iter()
            .min_by_key(|(_, s)| s.last_seen)
            .map(|(k, _)| *k)
        {
            self.streams.remove(&oldest);
        }
        if self.head_requests.len() > MAX_HTTP1_STREAMS {
            self.head_requests.clear();
        }
    }
}

enum Step {
    NeedMore,
    Complete,
    Error,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ev(ts: u64) -> Event {
        Event::new_with_timestamp(ts, "ssl".into(), 1, "t".into(), json!({}))
    }

    fn consumed(f: Feed) -> Vec<Http1Message> {
        match f {
            Feed::Consumed(m) => m,
            Feed::NotHttp1 => panic!("expected Consumed"),
        }
    }

    #[test]
    fn request_body_split_across_writes() {
        let mut t = Http1Tracker::default();
        let body = vec![0xC3u8; 40_000];
        let mut bytes = format!("POST /v1/messages HTTP/1.1\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        bytes.extend(&body);
        let mut out = Vec::new();
        for (i, part) in bytes.chunks(16384).enumerate() {
            out.extend(consumed(t.feed(&ev(i as u64), 7, 1, part)));
        }
        assert_eq!(out.len(), 1);
        assert!(out[0].is_request);
        assert_eq!(out[0].body, body);
        assert_eq!(out[0].first_event.timestamp, 0);
    }

    #[test]
    fn chunked_response_interleaved_with_other_connection() {
        let mut t = Http1Tracker::default();
        let a = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";
        let b = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
        let a2 = b"6\r\n world\r\n0\r\n\r\n";
        assert!(consumed(t.feed(&ev(1), 10, 0, a)).is_empty());
        let other = consumed(t.feed(&ev(2), 20, 0, b));
        assert_eq!(other.len(), 1);
        assert_eq!(other[0].body, b"{}");
        let done = consumed(t.feed(&ev(3), 10, 0, a2));
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].body, b"hello world");
        assert!(done[0].was_chunked);
        assert_eq!(done[0].last_timestamp, 3);
    }

    #[test]
    fn head_response_and_no_body_statuses() {
        let mut t = Http1Tracker::default();
        assert_eq!(consumed(t.feed(&ev(1), 5, 1, b"HEAD /x HTTP/1.1\r\nHost: h\r\n\r\n")).len(), 1);
        let r = consumed(t.feed(&ev(2), 5, 0, b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n"));
        assert_eq!(r.len(), 1);
        assert!(r[0].body.is_empty());
        let r = consumed(t.feed(&ev(3), 5, 0, b"HTTP/1.1 304 Not Modified\r\n\r\n"));
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn pipelined_messages_in_one_event() {
        let mut t = Http1Tracker::default();
        let bytes = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\nPOST /b HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc";
        let out = consumed(t.feed(&ev(1), 5, 1, bytes));
        assert_eq!(out.len(), 2);
        assert_eq!(out[1].body, b"abc");
    }

    #[test]
    fn mid_stream_and_http2_are_not_http1() {
        let mut t = Http1Tracker::default();
        assert!(matches!(t.feed(&ev(1), 5, 0, b"\x1f\x8b\x08garbage"), Feed::NotHttp1));
        assert!(matches!(t.feed(&ev(2), 5, 1, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), Feed::NotHttp1));
        assert!(!starts_like_http1(b"GET / HTTP/2\r\n"));
    }

    #[test]
    fn upgrade_hands_connection_back() {
        let mut t = Http1Tracker::default();
        consumed(t.feed(&ev(1), 5, 1, b"GET /ws HTTP/1.1\r\nUpgrade: websocket\r\n\r\n"));
        let r = consumed(t.feed(&ev(2), 5, 0, b"HTTP/1.1 101 Switching Protocols\r\n\r\n"));
        assert_eq!(r.len(), 1);
        assert!(matches!(t.feed(&ev(3), 5, 1, b"GET /not-http-anymore HTTP/1.1\r\n\r\n"), Feed::NotHttp1));
    }

    #[test]
    fn bad_chunk_size_resets_stream() {
        let mut t = Http1Tracker::default();
        let out = consumed(t.feed(&ev(1), 5, 0, b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"));
        assert!(out.is_empty());
        // Next message on the connection is framed normally again.
        let out = consumed(t.feed(&ev(2), 5, 0, b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx"));
        assert_eq!(out.len(), 1);
    }
}
