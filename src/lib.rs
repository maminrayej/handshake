use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

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
    svar: Arc<Condvar>,
    r2_syn: Arc<AtomicU64>,
    r2: Arc<AtomicU64>,
    reset: Arc<AtomicBool>,
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
    svar: Arc<Condvar>,
    reset: Arc<AtomicBool>,
}

#[derive(Debug, Default)]
pub struct Manager {
    iss: Arc<AtomicU32>,
    bounded: HashSet<u16>,
    pending: HashMap<Quad, TCB>,
    established: HashMap<u16, EstabEntry>,
    streams: HashMap<Quad, StreamEntry>,
}

#[derive(Debug)]
pub struct NetStack {
    manager: Arc<Mutex<Manager>>,
    jh: thread::JoinHandle<()>,
    ih: thread::JoinHandle<()>,
}

impl NetStack {
    pub fn new(name: &str, addr: Ipv4Addr, mask: Ipv4Addr) -> Result<Self, Error> {
        let tun = Tun::new(name, false)?;
        tun.set_addr(addr)?;
        tun.set_netmask(mask)?;
        tun.bring_up()?;

        let iss = Arc::new(AtomicU32::new(0));

        let ih = {
            let iss = iss.clone();

            thread::spawn(move || loop {
                thread::sleep(Duration::from_millis(4));

                iss.fetch_add(1, Ordering::Release);
            })
        };

        let manager = Arc::new(Mutex::new(Manager {
            iss,
            bounded: HashSet::new(),
            pending: HashMap::new(),
            established: HashMap::new(),
            streams: HashMap::new(),
        }));

        let jh = {
            let manager = manager.clone();

            thread::spawn(move || segment_loop(tun, manager.clone()))
        };

        Ok(NetStack { manager, jh, ih })
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
        self.ih.join().unwrap();
    }
}

fn segment_loop(mut tun: Tun, manager: Arc<Mutex<Manager>>) -> ! {
    loop {
        let mut buf = [0u8; 1500];

        let mut manager = manager.lock().unwrap();

        let mut to_be_deleted = vec![];
        for (quad, entry) in manager.streams.iter_mut() {
            if entry.tcb.on_tick(&mut tun) {
                to_be_deleted.push(*quad);
            }
        }
        for quad in to_be_deleted {
            manager.streams.remove(&quad).unwrap();
        }

        let mut to_be_deleted = vec![];
        for (quad, tcb) in manager.pending.iter_mut() {
            if tcb.on_tick(&mut tun) {
                to_be_deleted.push(*quad);
            }
        }
        for quad in to_be_deleted {
            manager.streams.remove(&quad).unwrap();
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
            let mut tcb = TCB::listen(quad, manager.iss.load(Ordering::Acquire));

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
                let svar = Arc::new(Condvar::new());
                let r2 = tcb.r2.clone();
                let r2_syn = tcb.r2_syn.clone();
                let reset = Arc::new(AtomicBool::new(false));

                manager.streams.insert(
                    quad,
                    StreamEntry {
                        tcb,
                        rvar: rvar.clone(),
                        wvar: wvar.clone(),
                        svar: svar.clone(),
                        reset: reset.clone(),
                    },
                );

                let EstabEntry { cvar, elts } = manager.established.get_mut(&dst.port).unwrap();
                elts.push(EstabElement {
                    quad,
                    rvar,
                    wvar,
                    svar,
                    r2,
                    r2_syn,
                    reset,
                });
                cvar.notify_one();
            }
            Action::Reset => {
                let stream = manager.streams.remove(&quad).unwrap();

                stream.reset.store(true, Ordering::Release);
                stream.rvar.notify_one();
                stream.wvar.notify_one();
                stream.svar.notify_one();
            }
            Action::Wakeup {
                wake_up_reader,
                wake_up_writer,
                wake_up_closer,
            } => {
                let StreamEntry {
                    rvar, wvar, svar, ..
                } = &manager.streams[&quad];

                if wake_up_reader {
                    rvar.notify_one();
                }
                if wake_up_writer {
                    wvar.notify_one();
                }
                if wake_up_closer {
                    svar.notify_one();
                }
            }
            Action::DeleteTCB => {
                todo!()
            }
            Action::ConnectionRefused => {
                todo!()
            }
        }
    }
}
