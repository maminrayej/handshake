use std::cmp;
use std::io::{self, Read, Write};
use std::sync::{Arc, Condvar, Mutex};

use crate::{Error, Manager};

use super::Quad;

#[derive(Debug)]
pub struct TcpStream {
    pub(crate) manager: Arc<Mutex<Manager>>,
    pub(crate) quad: Quad,
    pub(crate) rvar: Arc<Condvar>,
    pub(crate) wvar: Arc<Condvar>,
    pub(crate) closed: bool,
}

impl TcpStream {
    pub fn close(&mut self) {
        let mut manager = self.manager.lock().unwrap();

        self.closed = true;

        manager.streams.get_mut(&self.quad).unwrap().tcb.close();

        // TODO: Block until our fin has been acked.
    }
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
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
                })
                .unwrap();
        }

        let incoming = &mut manager
            .streams
            .get_mut(&self.quad)
            .ok_or(Error::StreamClosed(self.quad.src))?
            .tcb
            .incoming;

        let end = cmp::min(buf.len(), incoming.len());

        let data: Vec<u8> = incoming.drain(..end).collect();

        buf[..data.len()].copy_from_slice(&data[..]);

        return Ok(data.len());
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
                })
                .unwrap();
        }

        let outgoing = &mut manager
            .streams
            .get_mut(&self.quad)
            .ok_or(Error::StreamClosed(self.quad.src))?
            .tcb
            .outgoing;

        let len = cmp::min(buf.len(), outgoing.capacity());

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
                })
                .unwrap();
        }

        drop(manager);

        Ok(())
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        self.close();
    }
}
