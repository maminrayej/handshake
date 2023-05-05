use std::cmp;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
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
    pub(crate) closed: bool,
    pub(crate) reset: Arc<AtomicBool>,
}

impl TcpStream {
    pub fn close(&mut self) {
        let mut manager = self.manager.lock().unwrap();

        self.closed = true;

        manager.streams.get_mut(&self.quad).unwrap().tcb.close();

        // TODO: Do something about the spurious wake ups
        manager = self.svar.wait(manager).unwrap();

        drop(manager)
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

        let incoming = &mut manager
            .streams
            .get_mut(&self.quad)
            .ok_or(Error::StreamClosed(self.quad.src))?
            .tcb
            .incoming;

        let end = cmp::min(buf.len(), incoming.len());

        let data: Vec<u8> = incoming.drain(..end).collect();

        buf[..data.len()].copy_from_slice(&data[..]);

        // TODO: Update TCB rcv.wnd based on Receiver SWA

        /*
                RFC9293 S3.8.6.2.2. Receiver's Algorithm -- When to Send a Window Update

        A TCP implementation MUST include a SWS avoidance algorithm in the
        receiver (MUST-39).

         The receiver's SWS avoidance algorithm determines when the right
         window edge may be advanced; this is customarily known as "updating
         the window". This algorithm combines with the delayed ACK algorithm
         to determine when an ACK segment containing the current window will
         really be sent to the receiver. The solution to receiver SWS is to
         avoid advancing the right window edge RCV.NXT+RCV.WND in small increments,
         even if data is received from the network in small segments.

         Suppose the total receive buffer space is RCV.BUFF. At any given
         moment, RCV.USER octets of this total may be tied up with data that
         has been received and acknowledged but that the user process has not
         yet consumed. When the connection is quiescent, RCV.WND = RCV.BUFF
         and RCV.USER = 0.

        Keeping the right window edge fixed as data arrives and is
        acknowledged requires that the receiver offer less than its full
        buffer space, i.e., the receiver must specify a RCV.WND that keeps
        RCV.NXT+RCV.WND constant as RCV.NXT increases. Thus, the total buffer
        space RCV.BUFF is generally divided into three parts:

               |<------- RCV.BUFF ---------------->|
                    1             2            3
           ----|---------|------------------|------|----
                      RCV.NXT               ^
                                         (Fixed)

           1 - RCV.USER =  data received but not yet consumed;
           2 - RCV.WND =   space advertised to sender;
           3 - Reduction = space available but not yet
                           advertised.

        The suggested SWS avoidance algorithm for the receiver is to keep
        RCV.NXT+RCV.WND fixed until the reduction satisfies:

            RCV.BUFF - RCV.USER - RCV.WND  >=  min( Fr * RCV.BUFF, Eff.snd.MSS )

        where Fr is a fraction whose recommended value is 1/2, and
        Eff.snd.MSS is the effective send MSS for the connection.
        When the inequality is satisfied, RCV.WND is set to RCV.BUFF-RCV.USER.
        */

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
