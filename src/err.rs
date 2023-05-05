use std::io;

use crate::tcp::Dual;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Tun error: {0}")]
    TunError(#[from] tidy_tuntap::error::Error),

    #[error("Port: {0} has been unexpectedly closed")]
    PortClosed(u16),

    #[error("Port: {0} already in use")]
    PortInUse(u16),

    #[error("Stream: {0:?} has been unexpectedly closed")]
    StreamClosed(Dual),
}

impl From<Error> for io::Error {
    fn from(value: Error) -> Self {
        io::Error::new(io::ErrorKind::Other, value)
    }
}
