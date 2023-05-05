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
            .0
            .incoming
            .is_empty()
        {
            println!("Incoming is empty. Waiting...");

            manager = self
                .rvar
                .wait_while(manager, |manager| {
                    manager.streams[&self.quad].0.incoming.is_empty()
                })
                .unwrap();
        }

        println!("Waiting is over!");

        let incoming = &mut manager
            .streams
            .get_mut(&self.quad)
            .ok_or(Error::StreamClosed(self.quad.src))?
            .0
            .incoming;

        let end = cmp::min(buf.len(), incoming.len());

        let data: Vec<u8> = incoming.drain(..end).collect();

        println!("Drained data len: {}", data.len());

        buf[..data.len()].copy_from_slice(&data[..]);

        return Ok(data.len());
    }
}
