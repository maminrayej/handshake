use std::sync::{Arc, Condvar, Mutex};

use crate::{Error, EstabElement, Manager};

use super::stream::TcpStream;

#[derive(Debug)]
pub struct TcpListener {
    pub(crate) port: u16,
    pub(crate) manager: Arc<Mutex<Manager>>,
    pub(crate) cvar: Arc<Condvar>,
}

impl TcpListener {
    pub fn accept(&self) -> Result<TcpStream, Error> {
        let mut manager = self.manager.lock().unwrap();

        if manager.established[&self.port].elts.is_empty() {
            // FIXME: This will panic. use get() instead
            manager = self
                .cvar
                .wait_while(manager, |manager| {
                    manager.established[&self.port].elts.is_empty()
                })
                .unwrap();
        }

        let establisheds = manager
            .established
            .get_mut(&self.port)
            .ok_or(Error::PortClosed(self.port))?;

        let EstabElement { quad, rvar, wvar } = establisheds.elts.pop().unwrap();

        Ok(TcpStream {
            manager: self.manager.clone(),
            quad,
            rvar,
            wvar,
            closed: false,
        })
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        let mut manager = self.manager.lock().unwrap();

        assert!(manager.bounded.remove(&self.port));
    }
}
