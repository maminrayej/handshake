use std::cmp;
use std::io::{self, Read};
use std::sync::{Arc, Condvar, Mutex};

use crate::{Error, Manager};

use super::Quad;

#[derive(Debug)]
pub struct TcpStream {
    pub(crate) manager: Arc<Mutex<Manager>>,
    pub(crate) quad: Quad,
    pub(crate) rvar: Arc<Condvar>,
    pub(crate) wvar: Arc<Condvar>,
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
