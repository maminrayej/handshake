#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Tun error: {0}")]
    TunError(#[from] tidy_tuntap::error::Error),

    #[error("Port: {0} has been unexpectedly closed")]
    PortClosed(u16),

    #[error("Port: {0} already in use")]
    PortInUse(u16),
}
