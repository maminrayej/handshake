use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};
use nix::poll::{poll, PollFd, PollFlags};
use tidy_tuntap::Tun;

mod err;
pub use err::*;

mod tcp;
use tcp::{write_reset, Action, Dual, Quad, TcpListener, TCB};

#[derive(Debug)]
pub struct EstabElement {
    quad: Quad,
    rvar: Arc<Condvar>,
    wvar: Arc<Condvar>,
}

#[derive(Debug)]
pub struct EstabEntry {
    cvar: Arc<Condvar>,
    elts: Vec<EstabElement>,
}

#[derive(Debug)]
pub struct StreamEntry {
    tcb: TCB,
    rvar: Arc<Condvar>,
    wvar: Arc<Condvar>,
}

#[derive(Debug, Default)]
pub struct Manager {
    bounded: HashSet<u16>,
    pending: HashMap<Quad, TCB>,
    established: HashMap<u16, EstabEntry>,
    streams: HashMap<Quad, StreamEntry>,
}

#[derive(Debug)]
pub struct NetStack {
    manager: Arc<Mutex<Manager>>,
    jh: thread::JoinHandle<()>,
}

impl NetStack {
    pub fn new(name: &str, addr: Ipv4Addr, mask: Ipv4Addr) -> Result<Self, Error> {
        let tun = Tun::new(name, false)?;
        tun.set_addr(addr)?;
        tun.set_netmask(mask)?;
        tun.bring_up()?;

        let manager = Arc::new(Mutex::new(Manager::default()));

        let jh = {
            let manager = manager.clone();

            thread::spawn(move || segment_loop(tun, manager.clone()))
        };

        Ok(NetStack { manager, jh })
    }

    pub fn bind(&mut self, port: u16) -> Result<TcpListener, Error> {
        let mut manager = self.manager.lock().unwrap();

        match manager.established.entry(port) {
            Entry::Occupied(_) => {
                return Err(Error::PortInUse(port));
            }
            Entry::Vacant(v) => {
                let cvar = Arc::new(Condvar::new());

                v.insert(EstabEntry {
                    cvar: cvar.clone(),
                    elts: Vec::new(),
                });

                assert!(manager.bounded.insert(port));

                return Ok(TcpListener {
                    port,
                    manager: self.manager.clone(),
                    cvar,
                });
            }
        }
    }

    pub fn join(self) {
        self.jh.join().unwrap();
    }
}

fn segment_loop(mut tun: Tun, manager: Arc<Mutex<Manager>>) -> ! {
    loop {
        let mut buf = [0u8; 1500];

        let mut manager = manager.lock().unwrap();

        for entry in manager.streams.values_mut() {
            entry.tcb.on_tick(&mut tun);
        }

        let mut pfd = [PollFd::new(tun.as_raw_fd(), PollFlags::POLLIN)];
        if poll(&mut pfd[..], 1).unwrap() == 0 {
            continue;
        }
        let n = tun.read(&mut buf).unwrap();

        let Ok(ip4h) = Ipv4HeaderSlice::from_slice(&buf[..n]) else { continue };
        let Ok(tcph) = TcpHeaderSlice::from_slice(&buf[(ip4h.ihl() * 4) as usize..n]) else { continue };
        let data = &buf[(ip4h.ihl() * 4 + tcph.data_offset() * 4) as usize..n];

        let src = Dual {
            ipv4: ip4h.source_addr(),
            port: tcph.source_port(),
        };
        let dst = Dual {
            ipv4: ip4h.destination_addr(),
            port: tcph.destination_port(),
        };

        let quad = Quad { src, dst };

        let action = if let Some(StreamEntry { tcb, .. }) = manager.streams.get_mut(&quad) {
            tcb.on_segment(ip4h, tcph, data, &mut tun)
        } else if let Some(tcb) = manager.pending.get_mut(&quad) {
            tcb.on_segment(ip4h, tcph, data, &mut tun)
        } else if manager.bounded.contains(&dst.port) {
            let mut tcb = TCB::listen(quad);

            tcb.on_segment(ip4h, tcph, data, &mut tun)
        } else {
            /*
            If the connection does not exist (CLOSED), then a reset is sent
            in response to any incoming segment except another reset. A SYN
            segment that does not match an existing connection is rejected
            by this means.

            If the incoming segment has the ACK bit set, the reset takes its
            sequence number from the ACK field of the segment; otherwise,
            the reset has sequence number zero and the ACK field is set to
            the sum of the sequence number and segment length of the
            incoming segment. The connection remains in the CLOSED state.
            */

            if tcph.rst() {
                continue;
            }

            write_reset(&ip4h, &tcph, data, &mut tun);

            Action::Noop
        };

        match action {
            Action::Noop => continue,
            Action::AddToPending(tcb) => {
                manager.pending.insert(quad, tcb);
            }
            Action::RemoveFromPending => {
                manager.pending.remove(&quad);
            }
            Action::IsEstablished => {
                let tcb = manager.pending.remove(&quad).unwrap();
                let rvar = Arc::new(Condvar::new());
                let wvar = Arc::new(Condvar::new());

                manager.streams.insert(
                    quad,
                    StreamEntry {
                        tcb,
                        rvar: rvar.clone(),
                        wvar: wvar.clone(),
                    },
                );

                let EstabEntry { cvar, elts } = manager.established.get_mut(&dst.port).unwrap();
                elts.push(EstabElement { quad, rvar, wvar });
                cvar.notify_one();
            }
            Action::Reset => {
                // TODO: Signal any read() or write() that the connection has been reset.

                manager.streams.remove(&quad).unwrap();
            }
            Action::WakeUpReader => {
                let StreamEntry { rvar, .. } = &manager.streams[&quad];

                rvar.notify_one();
            }
        }
    }
}
