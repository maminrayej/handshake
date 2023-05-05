use std::sync::{Arc, Condvar, Mutex};

use crate::{Error, Manager};

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

        if manager.established[&self.port].1.is_empty() {
            manager = self
                .cvar
                .wait_while(manager, |manager| {
                    manager.established[&self.port].1.is_empty()
                })
                .unwrap();
        }

        let establisheds = manager
            .established
            .get_mut(&self.port)
            .ok_or(Error::PortClosed(self.port))?;

        let (quad, rvar, wvar) = establisheds.1.pop().unwrap();

        Ok(TcpStream {
            manager: self.manager.clone(),
            quad,
            rvar,
            wvar,
        })
    }
}
