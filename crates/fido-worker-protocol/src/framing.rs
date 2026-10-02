//! Length-prefixed frame codec shared by both ends of a process-boundary worker transport.
//!
//! A frame is a 4-byte big-endian payload length followed by exactly that many payload bytes.
//! The declared length is checked against the caller's bound **before** any payload is read or
//! allocated, and payload memory only grows as bytes actually arrive. Zero-length frames, short
//! reads, and payloads that are not valid messages are distinct, typed failures: a transport must
//! treat every one of them as a protocol violation, never as "try again".

use std::fmt;
use std::io::{self, Read, Write};

use serde::Serialize;
use serde::de::DeserializeOwned;

pub const FRAME_HEADER_BYTES: usize = 4;

/// Upper bound on the up-front payload allocation. Larger frames grow with the bytes received.
const INITIAL_PAYLOAD_CAPACITY: usize = 4_096;

#[derive(Debug)]
pub enum FrameError {
    /// Clean end of stream exactly at a frame boundary (peer closed or died between frames).
    Eof,
    /// End of stream inside a frame header or payload.
    Truncated,
    /// Declared or outgoing payload length exceeds the caller's bound.
    TooLarge,
    /// Zero-length frames carry no message and are never valid.
    Empty,
    /// The payload was fully received but is not a valid message of the expected type.
    Malformed,
    Io(io::Error),
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Eof => "stream closed at a frame boundary",
            Self::Truncated => "stream ended inside a frame",
            Self::TooLarge => "frame exceeds the configured bound",
            Self::Empty => "zero-length frame",
            Self::Malformed => "frame payload is not a valid message",
            Self::Io(_) => "frame transport I/O failure",
        })
    }
}

impl std::error::Error for FrameError {}

/// Writes one frame. The bound is enforced on the outgoing side too so a sender cannot emit a
/// frame its peer is required to reject.
pub fn write_frame<W: Write>(
    writer: &mut W,
    payload: &[u8],
    max_payload_bytes: usize,
) -> Result<(), FrameError> {
    if payload.is_empty() {
        return Err(FrameError::Empty);
    }
    if payload.len() > max_payload_bytes {
        return Err(FrameError::TooLarge);
    }
    let declared = u32::try_from(payload.len()).map_err(|_| FrameError::TooLarge)?;

    let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
    frame.extend_from_slice(&declared.to_be_bytes());
    frame.extend_from_slice(payload);
    writer.write_all(&frame).map_err(FrameError::Io)?;
    writer.flush().map_err(FrameError::Io)
}

/// Reads one frame, rejecting an over-bound or empty declaration before touching the payload.
pub fn read_frame<R: Read>(
    reader: &mut R,
    max_payload_bytes: usize,
) -> Result<Vec<u8>, FrameError> {
    let mut header = [0u8; FRAME_HEADER_BYTES];
    let mut filled = 0;
    while filled < header.len() {
        match reader.read(&mut header[filled..]) {
            Ok(0) if filled == 0 => return Err(FrameError::Eof),
            Ok(0) => return Err(FrameError::Truncated),
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(FrameError::Io(error)),
        }
    }

    let declared = usize::try_from(u32::from_be_bytes(header)).map_err(|_| FrameError::TooLarge)?;
    if declared == 0 {
        return Err(FrameError::Empty);
    }
    if declared > max_payload_bytes {
        return Err(FrameError::TooLarge);
    }

    let mut payload = Vec::with_capacity(declared.min(INITIAL_PAYLOAD_CAPACITY));
    let received = reader
        .take(declared as u64)
        .read_to_end(&mut payload)
        .map_err(FrameError::Io)?;
    if received != declared {
        return Err(FrameError::Truncated);
    }
    Ok(payload)
}

pub fn encode_message<T: Serialize>(message: &T) -> Result<Vec<u8>, FrameError> {
    serde_json::to_vec(message).map_err(|_| FrameError::Malformed)
}

pub fn decode_message<T: DeserializeOwned>(payload: &[u8]) -> Result<T, FrameError> {
    serde_json::from_slice(payload).map_err(|_| FrameError::Malformed)
}

pub fn write_message<W: Write, T: Serialize>(
    writer: &mut W,
    message: &T,
    max_payload_bytes: usize,
) -> Result<(), FrameError> {
    write_frame(writer, &encode_message(message)?, max_payload_bytes)
}

pub fn read_message<R: Read, T: DeserializeOwned>(
    reader: &mut R,
    max_payload_bytes: usize,
) -> Result<T, FrameError> {
    decode_message(&read_frame(reader, max_payload_bytes)?)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    const BOUND: usize = 64;

    fn frame_bytes(declared: u32, payload: &[u8]) -> Vec<u8> {
        let mut bytes = declared.to_be_bytes().to_vec();
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn frame_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let mut wire = Vec::new();
        write_frame(&mut wire, b"hello", BOUND)?;
        assert_eq!(wire, frame_bytes(5, b"hello"));
        assert_eq!(read_frame(&mut Cursor::new(wire), BOUND)?, b"hello");
        Ok(())
    }

    #[test]
    fn consecutive_frames_are_read_independently() -> Result<(), Box<dyn std::error::Error>> {
        let mut wire = Vec::new();
        write_frame(&mut wire, b"one", BOUND)?;
        write_frame(&mut wire, b"two", BOUND)?;
        let mut reader = Cursor::new(wire);
        assert_eq!(read_frame(&mut reader, BOUND)?, b"one");
        assert_eq!(read_frame(&mut reader, BOUND)?, b"two");
        assert!(matches!(
            read_frame(&mut reader, BOUND),
            Err(FrameError::Eof)
        ));
        Ok(())
    }

    #[test]
    fn empty_stream_is_clean_eof() {
        assert!(matches!(
            read_frame(&mut Cursor::new(Vec::new()), BOUND),
            Err(FrameError::Eof)
        ));
    }

    #[test]
    fn partial_header_is_truncated_not_eof() {
        for length in 1..FRAME_HEADER_BYTES {
            let wire = vec![0u8; length];
            assert!(matches!(
                read_frame(&mut Cursor::new(wire), BOUND),
                Err(FrameError::Truncated)
            ));
        }
    }

    #[test]
    fn short_payload_is_truncated() {
        let wire = frame_bytes(10, b"short");
        assert!(matches!(
            read_frame(&mut Cursor::new(wire), BOUND),
            Err(FrameError::Truncated)
        ));
    }

    #[test]
    fn declared_length_over_bound_is_rejected_before_any_payload_read() {
        /// Serves the header, then fails the test if the codec reads on.
        struct HeaderOnly {
            header: Vec<u8>,
            served: usize,
        }
        impl Read for HeaderOnly {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if self.served >= self.header.len() {
                    return Err(io::Error::other("codec read past the header"));
                }
                let count = buffer.len().min(self.header.len() - self.served);
                buffer[..count].copy_from_slice(&self.header[self.served..self.served + count]);
                self.served += count;
                Ok(count)
            }
        }

        for declared in [BOUND as u32 + 1, 1 << 24, u32::MAX] {
            let mut reader = HeaderOnly {
                header: declared.to_be_bytes().to_vec(),
                served: 0,
            };
            assert!(matches!(
                read_frame(&mut reader, BOUND),
                Err(FrameError::TooLarge)
            ));
        }
    }

    #[test]
    fn declared_length_at_bound_is_accepted() -> Result<(), Box<dyn std::error::Error>> {
        let payload = vec![7u8; BOUND];
        let wire = frame_bytes(BOUND as u32, &payload);
        assert_eq!(read_frame(&mut Cursor::new(wire), BOUND)?, payload);
        Ok(())
    }

    #[test]
    fn zero_length_frame_is_rejected() {
        assert!(matches!(
            read_frame(&mut Cursor::new(frame_bytes(0, b"")), BOUND),
            Err(FrameError::Empty)
        ));
        assert!(matches!(
            write_frame(&mut Vec::new(), b"", BOUND),
            Err(FrameError::Empty)
        ));
    }

    #[test]
    fn oversize_outgoing_frame_is_refused() {
        let payload = vec![1u8; BOUND + 1];
        let mut wire = Vec::new();
        assert!(matches!(
            write_frame(&mut wire, &payload, BOUND),
            Err(FrameError::TooLarge)
        ));
        assert!(
            wire.is_empty(),
            "nothing may be emitted for a refused frame"
        );
    }

    #[test]
    fn payload_that_is_not_a_message_is_malformed() {
        assert!(matches!(
            decode_message::<crate::ParentHello>(b"not json"),
            Err(FrameError::Malformed)
        ));
        assert!(matches!(
            decode_message::<crate::ParentHello>(br#"{"unexpected":true}"#),
            Err(FrameError::Malformed)
        ));
    }
}
