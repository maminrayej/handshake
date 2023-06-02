use std::cmp;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use crate::{Error, Manager};

use super::Quad;

#[derive(Debug)]
pub struct TcpStream {
    pub(crate) manager: Arc<Mutex<Manager>>,
    pub(crate) quad: Quad,
    pub(crate) rvar: Arc<Condvar>,
    pub(crate) wvar: Arc<Condvar>,
    pub(crate) svar: Arc<Condvar>,
    pub(crate) r2_syn: Arc<AtomicU64>,
    pub(crate) r2: Arc<AtomicU64>,
    pub(crate) closed: bool,
    pub(crate) reset: Arc<AtomicBool>,
}

impl TcpStream {
    pub fn close(&mut self) {
        let mut manager = self.manager.lock().unwrap();

        self.closed = true;

        manager.streams.get_mut(&self.quad).unwrap().tcb.close();

        manager = self.svar.wait(manager).unwrap();

        drop(manager)
    }

    pub fn set_r2(&self, r2: u64) {
        self.r2.store(r2, Ordering::Release);
    }

    pub fn set_r2_syn(&self, r2: u64) {
        self.r2_syn.store(r2, Ordering::Release);
    }
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.reset.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "Connection has been reset",
            ));
        }

        let mut manager = self.manager.lock().unwrap();

        if manager
            .streams
            .get_mut(&self.quad)
            .ok_or(Error::StreamClosed(self.quad.src))?
            .tcb
            .incoming
            .is_empty()
        {
            manager = self
                .rvar
                .wait_while(manager, |manager| {
                    manager.streams[&self.quad].tcb.incoming.is_empty()
                        || !self.reset.load(Ordering::Acquire)
                })
                .unwrap();
        }

        if self.reset.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "Connection has been reset",
            ));
        }

        let len = manager
            .streams
            .get_mut(&self.quad)
            .ok_or(Error::StreamClosed(self.quad.src))?
            .tcb
            .recv(buf);

        return Ok(len);
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.closed {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Write half of the stream is closed",
            ));
        }

        if self.reset.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "Connection has been reset",
            ));
        }

        let mut manager = self.manager.lock().unwrap();

        if manager
            .streams
            .get_mut(&self.quad)
            .ok_or(Error::StreamClosed(self.quad.src))?
            .tcb
            .is_outgoing_full()
        {
            manager = self
                .wvar
                .wait_while(manager, |manager| {
                    manager.streams[&self.quad].tcb.is_outgoing_full()
                        || !self.reset.load(Ordering::Acquire)
                })
                .unwrap();
        }

        if self.reset.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "Connection has been reset",
            ));
        }

        let outgoing = &mut manager
            .streams
            .get_mut(&self.quad)
            .ok_or(Error::StreamClosed(self.quad.src))?
            .tcb
            .outgoing;

        let len = cmp::min(buf.len(), outgoing.capacity() - outgoing.len());

        outgoing.extend(buf[..len].iter());

        return Ok(len);
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut manager = self.manager.lock().unwrap();

        if !manager
            .streams
            .get_mut(&self.quad)
            .ok_or(Error::StreamClosed(self.quad.src))?
            .tcb
            .outgoing
            .is_empty()
        {
            manager = self
                .wvar
                .wait_while(manager, |manager| {
                    !manager.streams[&self.quad].tcb.outgoing.is_empty()
                        || !self.reset.load(Ordering::Acquire)
                })
                .unwrap();
        }

        drop(manager);

        if self.reset.load(Ordering::Acquire) {
            Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "Connection has been reset",
            ))
        } else {
            Ok(())
        }
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        self.close();
    }
}
