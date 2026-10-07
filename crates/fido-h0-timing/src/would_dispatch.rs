//! T6 endpoint: the would-be dispatch point.
//!
//! In the production design the service writes one request frame to the dedicated worker, and the
//! worker then enters the native call. H0 reproduces the host-side hop up to frame receipt: the
//! marker frame crosses a Unix socket to a thread, which timestamps it and discards it. That thread
//! owns no device handle (device sessions are not `Send` and never leave the measuring thread), so
//! receipt of the frame cannot lead to any authenticator command.

#[cfg(unix)]
pub use unix::SocketStub;

#[cfg(unix)]
mod unix {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc::{Receiver, channel};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    use crate::measurement::WouldDispatch;

    const MAX_FRAME: usize = 4096;

    pub struct SocketStub {
        writer: Option<UnixStream>,
        received: Receiver<Instant>,
        thread: Option<JoinHandle<()>>,
    }

    impl SocketStub {
        pub fn spawn() -> std::io::Result<Self> {
            let (writer, mut reader) = UnixStream::pair()?;
            let (sender, received) = channel();
            let thread = std::thread::Builder::new()
                .name("h0-would-dispatch".into())
                .spawn(move || {
                    let mut length = [0u8; 4];
                    let mut frame = vec![0u8; MAX_FRAME];
                    while reader.read_exact(&mut length).is_ok() {
                        let size = u32::from_le_bytes(length) as usize;
                        if size > MAX_FRAME || reader.read_exact(&mut frame[..size]).is_err() {
                            return;
                        }
                        // Received: this is the "ready to send" instant. The frame is discarded.
                        if sender.send(Instant::now()).is_err() {
                            return;
                        }
                    }
                })?;
            Ok(Self {
                writer: Some(writer),
                received,
                thread: Some(thread),
            })
        }
    }

    impl WouldDispatch for SocketStub {
        fn deliver(&mut self, frame: &[u8]) -> std::io::Result<Instant> {
            let size = u32::try_from(frame.len())
                .ok()
                .filter(|size| *size as usize <= MAX_FRAME)
                .ok_or_else(|| std::io::Error::other("frame too large"))?;
            let writer = self
                .writer
                .as_mut()
                .ok_or_else(|| std::io::Error::other("stub closed"))?;
            writer.write_all(&size.to_le_bytes())?;
            writer.write_all(frame)?;
            writer.flush()?;
            self.received
                .recv_timeout(Duration::from_secs(2))
                .map_err(std::io::Error::other)
        }
    }

    impl Drop for SocketStub {
        fn drop(&mut self) {
            drop(self.writer.take());
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn frames_are_received_after_they_are_sent() -> std::io::Result<()> {
            let mut stub = SocketStub::spawn()?;
            for _ in 0..3 {
                let sent = Instant::now();
                let received = stub.deliver(b"{\"kind\":\"marker\"}")?;
                assert!(received >= sent);
            }
            assert!(stub.deliver(&vec![0u8; MAX_FRAME + 1]).is_err());
            Ok(())
        }
    }
}
