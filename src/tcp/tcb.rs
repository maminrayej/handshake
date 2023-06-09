use std::cmp;
use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering::{self, Acquire};
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Arc;
use std::time::{Duration, Instant};

use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice, TcpOptionElement};
use tidy_tuntap::Tun;

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Dual {
    pub ipv4: Ipv4Addr,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Quad {
    pub src: Dual,
    pub dst: Dual,
}

/*
                    RFC 9293 - S3.3.2 - Fig 5

                            +---------+ ---------\      active OPEN
                            |  CLOSED |            \    -----------
                            +---------+<---------\   \   create TCB
                              |     ^              \   \  snd SYN
                 passive OPEN |     |   CLOSE        \   \
                 ------------ |     | ----------       \   \
                  create TCB  |     | delete TCB         \   \
                              V     |                      \   \
          rcv RST (note 1)  +---------+            CLOSE    |    \
       -------------------->|  LISTEN |          ---------- |     |
      /                     +---------+          delete TCB |     |
     /           rcv SYN      |     |     SEND              |     |
    /           -----------   |     |    -------            |     V
+--------+      snd SYN,ACK  /       \   snd SYN          +--------+
|        |<-----------------           ------------------>|        |
|  SYN   |                    rcv SYN                     |  SYN   |
|  RCVD  |<-----------------------------------------------|  SENT  |
|        |                  snd SYN,ACK                   |        |
|        |------------------           -------------------|        |
+--------+   rcv ACK of SYN  \       /  rcv SYN,ACK       +--------+
   |         --------------   |     |   -----------
   |                x         |     |     snd ACK
   |                          V     V
   |  CLOSE                 +---------+
   | -------                |  ESTAB  |
   | snd FIN                +---------+
   |                 CLOSE    |     |    rcv FIN
   V                -------   |     |    -------
+---------+         snd FIN  /       \   snd ACK         +---------+
|  FIN    |<----------------          ------------------>|  CLOSE  |
| WAIT-1  |------------------                            |   WAIT  |
+---------+          rcv FIN  \                          +---------+
  | rcv ACK of FIN   -------   |                          CLOSE  |
  | --------------   snd ACK   |                         ------- |
  V        x                   V                         snd FIN V
+---------+               +---------+                    +---------+
|FINWAIT-2|               | CLOSING |                    | LAST-ACK|
+---------+               +---------+                    +---------+
  |              rcv ACK of FIN |                 rcv ACK of FIN |
  |  rcv FIN     -------------- |    Timeout=2MSL -------------- |
  |  -------            x       V    ------------        x       V
   \ snd ACK              +---------+delete TCB          +---------+
     -------------------->|TIME-WAIT|------------------->| CLOSED  |
                          +---------+                    +---------+
*/
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Listen,
    SynRcvd,
    SynSent,
    Estab,
    FinWait1,
    FinWait2,
    Closing,
    TimeWait,
    CloseWait,
    LastAck,
}

/*
                RFC 9293 - S3.3.1 - Fig 3

           1         2          3          4
      ----------|----------|----------|----------
             SND.UNA    SND.NXT    SND.UNA
                                  +SND.WND

1 - old sequence numbers that have been acknowledged
2 - sequence numbers of unacknowledged data
3 - sequence numbers allowed for new data transmission
4 - future sequence numbers that are not yet allowed
*/
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendSpace {
    una: u32, // send unacknowledged
    nxt: u32, // send next
    wnd: u16, // send window
    urp: u16, // send urgent pointer
    wl1: u32, // segment sequence number used for last window update
    wl2: u32, // segment acknowledgment number used for last window update
    iss: u32, // initial send sequence number
    mss: u16, // sender maximum segment size

    max_wnd: u16, // maximum window that the receiver has advertised
}

/*
                RFC 9293 - S3.3.1 - Fig 4

                       1          2          3
                   ----------|----------|----------
                          RCV.NXT    RCV.NXT
                                    +RCV.WND

        1 - old sequence numbers that have been acknowledged
        2 - sequence numbers allowed for new reception
        3 - future sequence numbers that are not yet allowed
*/
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecvSpace {
    nxt: u32, // receive next
    wnd: u16, // receive window
    urp: u16, // receive urgent pointer
    irs: u32, // initial receive seqeunce number
    mss: u16, // receiver maximum segment size
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Active,
    Passive,
}

#[derive(Debug, Clone)]
pub enum Action {
    Noop,
    AddToPending(TCB),
    RemoveFromPending,
    IsEstablished,
    Reset,
    DeleteTCB,
    Wakeup {
        wake_up_reader: bool,
        wake_up_writer: bool,
        wake_up_closer: bool,
    },
    ConnectionRefused,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    sno: u32,
    una: u32,
    len: u32,
    fin: bool,
    syn: bool,
    ack: bool,

    retry: bool,
    total_ret_time: u128,
    sent: Option<Instant>,
    mss: Option<u16>,
}

impl Segment {
    fn end(&self) -> u32 {
        self.sno.wrapping_add(self.len).wrapping_sub(1)
    }

    fn unacked_data_len(&self) -> usize {
        (self.end().wrapping_sub(self.una) + 1) as usize - if self.fin { 1 } else { 0 }
    }
}

#[derive(Debug, Clone)]
pub struct TCB {
    pub(crate) quad: Quad,
    pub(crate) kind: Kind,
    pub(crate) state: State,
    pub(crate) reset: Arc<AtomicBool>,
    pub(crate) write_closed: Arc<AtomicBool>,
    pub(crate) read_closed: Arc<AtomicBool>,
    pub(crate) time_wait: Option<Instant>,

    pub(crate) snd: SendSpace,
    pub(crate) rcv: RecvSpace,

    pub(crate) srtt: u128,
    pub(crate) rttvar: u128,
    pub(crate) rto: u128,
    pub(crate) rtt_measured: bool,
    pub(crate) timeout: Option<Instant>,
    pub(crate) r1: u128,
    pub(crate) r2: Arc<AtomicU64>,
    pub(crate) r1_syn: u128,
    pub(crate) r2_syn: Arc<AtomicU64>,

    pub(crate) cwnd: u32,
    pub(crate) ssthresh: u32,

    pub(crate) probe_timeout: Option<Instant>,

    pub(crate) incoming: VecDeque<u8>,
    pub(crate) outgoing: VecDeque<u8>,
    pub(crate) segments: VecDeque<Segment>,
}

impl TCB {
    pub fn listen(quad: Quad, iss: u32) -> Self {
        TCB {
            quad,
            kind: Kind::Passive,
            state: State::Listen,
            reset: Arc::new(AtomicBool::new(false)),
            write_closed: Arc::new(AtomicBool::new(false)),
            read_closed: Arc::new(AtomicBool::new(false)),
            time_wait: None,
            snd: SendSpace {
                una: iss,
                nxt: iss,
                wnd: 0,
                urp: 0,
                wl1: 0,
                wl2: 0,
                iss,
                mss: 536,
                max_wnd: 0,
            },
            rcv: RecvSpace {
                nxt: 0,
                wnd: 64240,
                urp: 0,
                irs: 0,
                mss: 536,
            },
            srtt: 0,
            rttvar: 0,
            /*
            Until a round-trip time (RTT) measurement has been made for a
            segment sent between the sender and receiver, the sender SHOULD
            set RTO <- 1 second, though the "backing off" on repeated
            retransmission still applies.
            */
            rto: 1000,
            rtt_measured: false,
            timeout: None,
            r1: 50 * 1000,
            r2: Arc::new(AtomicU64::new(100 * 1000)),
            r1_syn: 1 * 60 * 1000,
            r2_syn: Arc::new(AtomicU64::new(3 * 60 * 1000)),
            /*
            IW, the initial value of cwnd, MUST be set using the following
            guidelines as an upper bound.

            If SMSS > 2190 bytes:
                IW = 2 * SMSS bytes and MUST NOT be more than 2 segments
            If (SMSS > 1095 bytes) and (SMSS <= 2190 bytes):
                IW = 3 * SMSS bytes and MUST NOT be more than 3 segments
            if SMSS <= 1095 bytes:
                IW = 4 * SMSS bytes and MUST NOT be more than 4 segments
            */
            cwnd: 4 * 536,
            /*
            The initial value of ssthresh SHOULD be set arbitrarily high (e.g.,
            to the size of the largest possible advertised window), but ssthresh
            MUST be reduced in response to congestion.  Setting ssthresh as high
            as possible allows the network conditions, rather than some arbitrary
            host limit, to dictate the sending rate.
            */
            ssthresh: u32::MAX,

            probe_timeout: None,

            incoming: VecDeque::new(),
            outgoing: VecDeque::new(),
            segments: VecDeque::new(),
        }
    }

    pub fn syn_sent(quad: Quad, iss: u32) -> Self {
        let mut tcb = TCB {
            quad,
            kind: Kind::Active,
            state: State::SynSent,
            reset: Arc::new(AtomicBool::new(false)),
            write_closed: Arc::new(AtomicBool::new(false)),
            read_closed: Arc::new(AtomicBool::new(false)),
            time_wait: None,
            snd: SendSpace {
                una: iss,
                nxt: iss,
                wnd: 0,
                urp: 0,
                wl1: 0,
                wl2: 0,
                iss,
                mss: 536,
                max_wnd: 0,
            },
            rcv: RecvSpace {
                nxt: 0,
                wnd: 64240,
                urp: 0,
                irs: 0,
                mss: 536,
            },
            srtt: 0,
            rttvar: 0,
            /*
            Until a round-trip time (RTT) measurement has been made for a
            segment sent between the sender and receiver, the sender SHOULD
            set RTO <- 1 second, though the "backing off" on repeated
            retransmission still applies.
            */
            rto: 1000,
            rtt_measured: false,
            timeout: None,
            r1: 50 * 1000,
            r2: Arc::new(AtomicU64::new(100 * 1000)),
            r1_syn: 1 * 60 * 1000,
            r2_syn: Arc::new(AtomicU64::new(3 * 60 * 1000)),
            /*
            IW, the initial value of cwnd, MUST be set using the following
            guidelines as an upper bound.

            If SMSS > 2190 bytes:
                IW = 2 * SMSS bytes and MUST NOT be more than 2 segments
            If (SMSS > 1095 bytes) and (SMSS <= 2190 bytes):
                IW = 3 * SMSS bytes and MUST NOT be more than 3 segments
            if SMSS <= 1095 bytes:
                IW = 4 * SMSS bytes and MUST NOT be more than 4 segments
            */
            cwnd: 4 * 536,
            /*
            The initial value of ssthresh SHOULD be set arbitrarily high (e.g.,
            to the size of the largest possible advertised window), but ssthresh
            MUST be reduced in response to congestion.  Setting ssthresh as high
            as possible allows the network conditions, rather than some arbitrary
            host limit, to dictate the sending rate.
            */
            ssthresh: u32::MAX,

            probe_timeout: None,

            incoming: VecDeque::new(),
            outgoing: VecDeque::new(),
            segments: VecDeque::new(),
        };

        tcb.segments.push_front(Segment {
            sno: tcb.snd.nxt,
            una: tcb.snd.nxt,
            len: 1,
            fin: false,
            syn: true,
            ack: false,
            retry: false,
            total_ret_time: 0,
            sent: None,
            mss: Some(tcb.rcv.mss),
        });

        tcb.snd.nxt = tcb.snd.iss.wrapping_add(1);

        tcb
    }

    fn is_slow_start(&self) -> bool {
        self.cwnd < self.ssthresh
    }

    pub fn is_outgoing_full(&self) -> bool {
        self.outgoing.capacity() == self.outgoing.len()
    }

    fn is_fin_acked(&self) -> bool {
        println!(
            "\t\tIs FIN acked: {}",
            self.outgoing.is_empty()
                && self.segments.is_empty()
                && self.snd.una == self.snd.nxt
                && self.write_closed.load(Ordering::Acquire)
        );

        self.outgoing.is_empty()
            && self.segments.is_empty()
            && self.snd.una == self.snd.nxt
            && self.write_closed.load(Ordering::Acquire)
    }

    fn available_data_len(&self) -> usize {
        let sent_len = self.snd.nxt.wrapping_sub(self.snd.una) as usize;
        let available_len = self.outgoing.len() - sent_len;

        available_len
    }

    fn sws_allows_send(&self) -> bool {
        /*
                RFC 9293 - S3.8.6.2.1. Sender's Algorithm -- When to Send Data

            The "usable window" is:

            U = SND.UNA + SND.WND - SND.NXT

            i.e., the offered window less the amount of data sent but not
            acknowledged. If D is the amount of data queued in the sending TCP
            endpoint but not yet sent, then the following set of rules is
            recommended.

            Send data:

            (1) if a maximum-sized segment can be sent, i.e., if:
                min(D,U) >= Eff.snd.MSS;

            (2) or if the data is pushed and all queued data can be sent now, i.e., if:
                [SND.NXT = SND.UNA and] PUSHed and D <= U
                (the bracketed condition is imposed by the Nagle algorithm);

            (3)  or if at least a fraction Fs of the maximum window can be sent, i.e., if:
                [SND.NXT = SND.UNA and] min(D,U) >= Fs * Max(SND.WND);

            (4) or if the override timeout occurs.

            Here Fs is a fraction whose recommended value is 1/2. The override
            timeout should be in the range 0.1 - 1.0 seconds. It may be
            convenient to combine this timer with the timer used to probe
            zero windows.
        */

        let d = self.available_data_len();
        let u = self
            .snd
            .una
            .wrapping_add(self.snd.wnd as u32)
            .wrapping_sub(self.snd.nxt) as usize;

        cmp::min(d, u) >= self.snd.mss as usize
            || d <= u
            || cmp::min(d, u) >= (0.5 * self.snd.max_wnd as f64) as usize
    }

    pub fn close(&mut self) {
        if self.state == State::Estab {
            println!("\t\tState <- FinWait1");
            self.state = State::FinWait1;
        } else {
            assert_eq!(self.state, State::CloseWait);

            println!("\t\tState <- LastAck");
            self.state = State::LastAck;
        }

        /*
        When we close the write half of the TCP stream, we must send a FIN.
        If there is any data available to be sent, FIN will be set on the last segment.
        But, if there isn't any more data to be sent, we must create an empty segment
        that contains no data and only contains the fin flag, and put it at the end of the queue.
        */
        if self.available_data_len() == 0 {
            let fin = Segment {
                sno: self.snd.nxt,
                una: self.snd.nxt,
                len: 1,
                fin: true,
                syn: false,
                ack: true,
                retry: false,
                total_ret_time: 0,
                sent: None,
                mss: None,
            };

            self.segments.push_back(fin);

            self.snd.nxt = self.snd.nxt.wrapping_add(1);
        }
    }

    pub fn recv(&mut self, buf: &mut [u8]) -> usize {
        let len = cmp::min(buf.len(), self.incoming.len());

        let data: Vec<u8> = self.incoming.drain(..len).collect();

        buf[..data.len()].copy_from_slice(&data[..]);

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

        if self.incoming.capacity() - self.incoming.len() - self.rcv.wnd as usize
            >= cmp::min(
                (0.5 * self.incoming.capacity() as f64) as usize,
                self.snd.mss as usize,
            )
        {
            self.rcv.wnd = (self.incoming.capacity() - self.incoming.len()) as u16;
        }

        len
    }

    pub fn on_tick(&mut self, tun: &mut Tun) -> bool {
        if let Some(timeout) = self.timeout.clone() {
            if Instant::now() >= timeout {
                println!("\t\tTimeout");
                let seg = self.segments.front_mut().unwrap();

                let data: Vec<u8> = self
                    .outgoing
                    .iter()
                    .cloned()
                    .take(seg.unacked_data_len())
                    .collect();

                println!(
                    "\t\t\tWriting {}bytes with flags: FIN: {}, SYN: {}, ACK: {}",
                    data.len(),
                    seg.fin,
                    seg.syn,
                    seg.ack
                );
                write_data(
                    self.quad,
                    seg.sno,
                    self.rcv.nxt,
                    self.rcv.wnd,
                    tun,
                    &data[..],
                    seg.fin,
                    seg.syn,
                    seg.ack,
                    seg.mss,
                );

                seg.retry = true;
                seg.total_ret_time += self.rto;
                seg.sent = Some(Instant::now());

                println!("\t\t\tBefore RTO: {}", self.rto);
                self.rto *= 2;
                println!("\t\t\tAfter RTO: {}", self.rto);

                self.timeout =
                    Some(seg.sent.clone().unwrap() + Duration::from_millis(self.rto as u64));

                /*
                        RFC 9293 S3.8.3. TCP Connection Failures

                Excessive retransmission of the same segment by a TCP endpoint
                indicates some failure of the remote host or the internetwork path.
                This failure may be of short or long duration. The following
                procedure MUST be used to handle excessive retransmissions of data
                segments (MUST-20):

                (a) There are two thresholds R1 and R2 measuring the amount of
                    retransmission that has occurred for the same segment. R1 and
                    R2 might be measured in time units or as a count of
                    retransmissions (with the current RTO and corresponding
                    backoffs as a conversion factor, if needed).

                (b) When the number of transmissions of the same segment reaches or
                    exceeds threshold R1, pass negative advice to the IP layer, to
                    trigger dead-gateway diagnosis.

                (c) When the number of transmissions of the same segment reaches
                    a threshold R2 greater than R1, close the connection.

                (d) An application MUST (MUST-21) be able to set the value for R2
                    for a particular connection. For example, an interactive
                    application might set R2 to "infinity", giving the user control
                    over when to disconnect.

                (e) TCP implementations SHOULD inform the application of the
                    delivery problem (unless such information has been disabled by
                    the application; see the "Asynchronous Reports" section, when
                    R1 is reached and before R2 (SHLD-9). This will allow a remote
                    login application program to inform the user, for example.

                The value of R1 SHOULD correspond to at least 3 retransmissions, at
                the current RTO (SHLD-10). The value of R2 SHOULD correspond to at
                least 100 seconds (SHLD-11).

                An attempt to open a TCP connection could fail with excessive
                retransmissions of the SYN segment or by receipt of a RST segment or
                an ICMP Port Unreachable. SYN retransmissions MUST be handled in the
                general way just described for data retransmissions, including
                notification of the application layer.

                However, the values of R1 and R2 may be different for SYN and data
                segments. In particular, R2 for a SYN segment MUST be set large
                enough to provide retransmission of the segment for at least 3
                minutes (MUST-23). The application can close the connection (i.e.,
                give up on the open attempt) sooner, of course.
                */
                if seg.syn {
                    if seg.total_ret_time > self.r1_syn {
                        println!("\t\t\tThreshold Syn-R1 reached");
                    } else if seg.total_ret_time as u64 > self.r2_syn.load(Acquire) {
                        println!("\t\t\tThreshold Syn-R2 reached. Terminating connection.");
                        return true;
                    }
                } else {
                    if seg.total_ret_time > self.r1 {
                        println!("\t\t\tThreshold R1 reached for {:?}", self.quad);
                    } else if seg.total_ret_time as u64 > self.r2.load(Acquire) {
                        println!("\t\t\tThreshold R2 reached. Terminating connection.");
                        return true;
                    }
                }
            }
        }

        if !self.outgoing.is_empty() {
            if self.sws_allows_send() {
                let sent_len = self.snd.nxt.wrapping_sub(self.snd.una) as usize;
                let available_len = self.outgoing.len() - sent_len;

                let to_be_sent = cmp::min(
                    cmp::min(available_len, self.cwnd as usize),
                    self.snd.wnd as usize,
                );

                if to_be_sent > 0 {
                    println!("\t\tOutgoing");
                    println!("\t\t\tsent_len: {sent_len}");
                    println!("\t\t\tto_be_sent: {to_be_sent}");
                    println!("\t\t\tavailable_len: {available_len}");

                    let data_len = cmp::min(to_be_sent, self.snd.mss as usize);
                    println!("\t\t\tData len: {data_len}");
                    let fin = data_len == to_be_sent && self.write_closed.load(Ordering::Acquire);

                    let data: Vec<u8> = self
                        .outgoing
                        .iter()
                        .copied()
                        .skip(sent_len)
                        .take(data_len)
                        .collect();

                    println!("\t\t\tWriting {}bytes with flags: FIN: {}", data.len(), fin,);
                    write_data(
                        self.quad,
                        self.snd.nxt,
                        self.rcv.nxt,
                        self.rcv.wnd,
                        tun,
                        data.as_slice(),
                        fin,
                        false,
                        true,
                        None,
                    );

                    let seg = Segment {
                        sno: self.snd.nxt,
                        una: self.snd.nxt,
                        len: data_len as u32,
                        fin,
                        syn: false,
                        ack: true,
                        retry: false,
                        total_ret_time: 0,
                        sent: Some(Instant::now()),
                        mss: None,
                    };

                    self.timeout =
                        Some(seg.sent.clone().unwrap() + Duration::from_millis(self.rto as u64));

                    self.segments.push_back(seg);

                    self.snd.nxt = self
                        .snd
                        .nxt
                        .wrapping_add(data_len as u32)
                        .wrapping_add(if fin { 1 } else { 0 });
                }
            }
        } else if !self.segments.is_empty() {
            let seg = self.segments.front_mut().unwrap();

            if seg.sent.is_none() {
                println!("\t\tSegment");

                println!(
                    "\t\t\tWriting segment with flags: FIN: {}, SYN: {}, ACK: {}",
                    seg.fin, seg.syn, seg.ack,
                );
                write_data(
                    self.quad,
                    seg.sno,
                    self.rcv.nxt,
                    self.rcv.wnd,
                    tun,
                    &[],
                    seg.fin,
                    seg.syn,
                    seg.ack,
                    seg.mss,
                );

                seg.sent = Some(Instant::now());

                if self.timeout.is_none() {
                    self.timeout =
                        Some(seg.sent.clone().unwrap() + Duration::from_millis(self.rto as u64));
                    println!("\t\t\tSetting timeout: {}ms", self.rto);
                }
            }
        }

        if let Some(time_wait) = self.time_wait.clone() {
            println!("\t\tTimewait");
            if time_wait >= Instant::now() {
                println!("\t\t\tTimewait reached, deleting TCB");
                return true;
            }
        }

        if let Some(probe_timeout) = self.probe_timeout.clone() {
            println!("\t\tProbe");
            /*
                    RFC 9293 S3.8.6.1. Zero-Window Probing

            The sending TCP peer must regularly transmit at least one octet of
            new data (if available), or retransmit to the receiving TCP peer even
            if the send window is zero, in order to "probe" the window. This
            retransmission is essential to guarantee that when either TCP peer
            has a zero window the reopening of the window will be reliably
            reported to the other. This is referred to as Zero-Window Probing
            (ZWP) in other documents.

            Probing of zero (offered) windows MUST be supported (MUST-36).

            A TCP implementation MAY keep its offered receive window closed
            indefinitely (MAY-8). As long as the receiving TCP peer continues to
            send acknowledgments in response to the probe segments, the sending
            TCP peer MUST allow the connection to stay open (MUST-37). This
            enables TCP to function in scenarios such as the "printer ran out of
            paper" situation described in Section 4.2.2.17 of [19]. The behavior
            is subject to the implementation's resource management concerns, as
            noted in [41].

            When the receiving TCP peer has a zero window and a segment arrives,
            it must still send an acknowledgment showing its next expected
            sequence number and current window (zero).

            The transmitting host SHOULD send the first zero-window probe when a
            zero window has existed for the retransmission timeout period
            (SHLD-29) (Section 3.8.1), and SHOULD increase exponentially the
            interval between successive probes (SHLD-30).
            */
            if probe_timeout >= Instant::now() {
                println!("\t\t\tWriting data to probe zero window");
                write_data(
                    self.quad,
                    self.snd.una.wrapping_sub(1),
                    self.rcv.nxt,
                    self.rcv.wnd,
                    tun,
                    &[0u8; 8],
                    false,
                    false,
                    true,
                    None,
                );

                self.probe_timeout = Some(Instant::now() + Duration::from_millis(self.rto as u64));
            }
        }

        false
    }

    fn process_ack(&mut self, ackno: u32) -> (bool, Option<u128>) {
        println!("\t\tProcess Ack");
        self.snd.una = ackno;

        let mut compute_rto = false;
        let mut r = 0;

        let before_len = self.outgoing.len();

        while !self.segments.is_empty() {
            let seg = self.segments.front_mut().unwrap();
            let end = seg.end();

            compute_rto = seg.retry == false;
            r = (Instant::now() - seg.sent.clone().unwrap()).as_millis();

            if is_between_wrapped(seg.una, ackno, end.wrapping_add(1)) {
                println!("\t\t\tPartial ack");
                // Partial acknowledgment

                let acked = ackno.wrapping_sub(seg.una);
                self.outgoing.drain(..acked as usize);

                seg.una = ackno;
            } else if wrapping_lt(end, ackno) {
                println!("\t\t\tFull ack");
                // Full acknowledgment

                let seg = self.segments.pop_front().unwrap();
                self.outgoing.drain(..seg.unacked_data_len());
            }
        }

        if self.segments.is_empty() {
            println!("\t\t\tNo more segments, turning off timer");
            self.timeout = None;
        } else {
            let seg = self.segments.front().unwrap();

            self.timeout = Some(seg.sent.clone().unwrap() + Duration::from_millis(self.rto as u64));
        }

        println!(
            "\t\t\tWrite is ready: {}, Compute RTO: {}",
            before_len < self.outgoing.len(),
            compute_rto
        );
        (before_len < self.outgoing.len(), compute_rto.then_some(r))
    }

    fn congestion_control(&mut self) {
        println!(
            "\t\tCongestion Control: snd.mss: {}, cwnd: {}, ssthresh: {}",
            self.snd.mss, self.cwnd, self.ssthresh
        );
        if self.is_slow_start() {
            println!("\t\t\tSlow start");
            /*
            During slow start, a TCP increments cwnd by at most SMSS bytes for
            each ACK received that cumulatively acknowledges new data.
            */
            self.cwnd += self.snd.mss as u32;
        } else {
            println!("\t\t\tCongestion avoidance");
            /*
            Another common formula that a TCP MAY use to update cwnd during
            congestion avoidance is given in equation (3):

                cwnd += SMSS*SMSS/cwnd                     (3)

            This adjustment is executed on every incoming ACK that acknowledges
            new data.  Equation (3) provides an acceptable approximation to the
            underlying principle of increasing cwnd by 1 full-sized segment per
            RTT.  (Note that for a connection in which the receiver is
            acknowledging every-other packet, (3) is less aggressive than allowed
            -- roughly increasing cwnd every second RTT.)

            Implementation Note: Since integer arithmetic is usually used in TCP
            implementations, the formula given in equation (3) can fail to
            increase cwnd when the congestion window is larger than SMSS*SMSS.
            If the above formula yields 0, the result SHOULD be rounded up to 1
            byte.
            */

            self.cwnd += cmp::max(
                ((self.snd.mss as f64 * self.snd.mss as f64) / self.cwnd as f64) as u32,
                1,
            );
        }
    }

    fn compute_rto(&mut self, r: u128) {
        println!("\t\tCompute RTO");
        /*
        -   When the first RTT measurement R is made, the host MUST set

                SRTT <- R
                RTTVAR <- R/2
                RTO <- SRTT + max (G, K*RTTVAR)

            where K = 4.

        -   When a subsequent RTT measurement R' is made, a host MUST set

                RTTVAR <- (1 - beta) * RTTVAR + beta * |SRTT - R'|
                SRTT <- (1 - alpha) * SRTT + alpha * R'

            The value of SRTT used in the update to RTTVAR is its value
            before updating SRTT itself using the second assignment.  That
            is, updating RTTVAR and SRTT MUST be computed in the above
            order.

            The above SHOULD be computed using alpha=1/8 and beta=1/4.

        -   After the computation, a host MUST update

                RTO <- SRTT + max (G, K*RTTVAR)
        */
        if !self.rtt_measured {
            self.srtt = r;
            self.rttvar = r / 2;
            self.rtt_measured = true;
        } else {
            self.rttvar =
                ((1.0 - 0.25) * self.rttvar as f64 + 0.25 * self.srtt.abs_diff(r) as f64) as u128;
            self.srtt = ((1.0 - 0.125) * self.srtt as f64 + 0.125 * r as f64) as u128;
        }

        self.rto = self.srtt + cmp::max(100, 4 * self.rttvar);

        /*
        Whenever RTO is computed, if it is less than 1 second, then the
        RTO SHOULD be rounded up to 1 second.
        */
        self.rto = cmp::max(self.rto, 1000);
    }

    pub fn on_segment(
        &mut self,
        ip4h: Ipv4HeaderSlice,
        tcph: TcpHeaderSlice,
        data: &[u8],
        tun: &mut Tun,
    ) -> Action {
        println!("\tOn Segment: {:?}", self.state);
        if self.state == State::Listen {
            /*
            If the state is LISTEN, then

            First, check for a RST:

            -   An incoming RST segment could not be valid since it could not
                have been sent in response to anything sent by this incarnation
                of the connection. An incoming RST should be ignored. Return.

            Second, check for an ACK:

            -   Any acknowledgment is bad if it arrives on a connection still
                in the LISTEN state. An acceptable reset segment should be
                formed for any arriving ACK-bearing segment. The RST should be
                formatted as follows:

                    <SEQ=SEG.ACK><CTL=RST>

            -   Return.

            Third, check for a SYN:

            -   If the SYN bit is set, check the security. If the
                security/compartment on the incoming segment does not exactly
                match the security/compartment in the TCB, then send a reset
                and return.

                    <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>

            -   Set RCV.NXT to SEG.SEQ+1, IRS is set to SEG.SEQ, and any other
                control or text should be queued for processing later. ISS
                should be selected and a SYN segment sent of the form:

                    <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>

            -   SND.NXT is set to ISS+1 and SND.UNA to ISS. The connection
                state should be changed to SYN-RECEIVED. Note that any other
                incoming control or data (combined with SYN) will be processed
                in the SYN-RECEIVED state, but processing of SYN and ACK should
                not be repeated. If the listen was not fully specified (i.e.,
                the remote socket was not fully specified), then the
                unspecified fields should be filled in now.

            Fourth, other data or control:
            -   This should not be reached. Drop the segment and return. Any
                other control or data-bearing segment (not containing SYN) must
                have an ACK and thus would have been discarded by the ACK
                processing in the second step, unless it was first discarded by
                RST checking in the first step.
            */

            if tcph.rst() {
                return Action::Noop;
            }

            if tcph.ack() {
                write_reset(&ip4h, &tcph, data, tun);

                return Action::Noop;
            }

            if tcph.syn() {
                let mss = tcph
                    .options_iterator()
                    .find_map(|op| match op.clone().unwrap() {
                        TcpOptionElement::MaximumSegmentSize(mss) => Some(mss),
                        _ => None,
                    })
                    .unwrap_or(536);

                self.rcv.nxt = tcph.sequence_number().wrapping_add(1);
                self.rcv.irs = tcph.sequence_number();

                self.snd.wnd = tcph.window_size();
                self.snd.max_wnd = tcph.window_size();
                self.snd.mss = mss;

                self.segments.push_front(Segment {
                    sno: self.snd.nxt,
                    una: self.snd.nxt,
                    len: 1,
                    fin: false,
                    syn: true,
                    ack: true,
                    retry: false,
                    total_ret_time: 0,
                    sent: None,
                    mss: None,
                });

                self.snd.nxt = self.snd.iss.wrapping_add(1);

                println!("\t\tState <- SynRcvd");
                self.state = State::SynRcvd;

                return Action::AddToPending(self.clone());
            }

            return Action::Noop;
        } else if self.state == State::SynSent {
            /*
            If the state is SYN-SENT, then

            First, check the ACK bit:

            If the ACK bit is set,

            If SEG.ACK =< ISS or SEG.ACK > SND.NXT, send a reset (unless the RST bit is set, if so drop the segment and return)
            <SEQ=SEG.ACK><CTL=RST>
            and discard the segment. Return. If SND.UNA < SEG.ACK =< SND.NXT, then the ACK is acceptable. Some deployed TCP code has used the check SEG.ACK == SND.NXT (using "==" rather than "=<"), but this is not appropriate when the stack is capable of sending data on the SYN because the TCP peer may not accept and acknowledge all of the data on the SYN.

            Second, check the RST bit:

            If the RST bit is set,
            A potential blind reset attack is described in RFC 5961 [9]. The mitigation described in that document has specific applicability explained therein, and is not a substitute for cryptographic protection (e.g., IPsec or TCP-AO). A TCP implementation that supports the mitigation described in RFC 5961 SHOULD first check that the sequence number exactly matches RCV.NXT prior to executing the action in the next paragraph.
            If the ACK was acceptable, then signal to the user "error: connection reset", drop the segment, enter CLOSED state, delete TCB, and return. Otherwise (no ACK), drop the segment and return.

            Third, check the security:

            If the security/compartment in the segment does not exactly match the security/compartment in the TCB, send a reset:

            If there is an ACK,
            <SEQ=SEG.ACK><CTL=RST>

            Otherwise,
            <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
            If a reset was sent, discard the segment and return.

            Fourth, check the SYN bit:
            This step should be reached only if the ACK is ok, or there is no ACK, and the segment did not contain a RST.
            If the SYN bit is on and the security/compartment is acceptable, then RCV.NXT is set to SEG.SEQ+1, IRS is set to SEG.SEQ. SND.UNA should be advanced to equal SEG.ACK (if there is an ACK), and any segments on the retransmission queue that are thereby acknowledged should be removed.

            If SND.UNA > ISS (our SYN has been ACKed), change the connection state to ESTABLISHED, form an ACK segment
            <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
            and send it. Data or controls that were queued for transmission MAY be included. Some TCP implementations suppress sending this segment when the received segment contains data that will anyways generate an acknowledgment in the later processing steps, saving this extra acknowledgment of the SYN from being sent. If there are other controls or text in the segment, then continue processing at the sixth step under Section 3.10.7.4 where the URG bit is checked; otherwise, return.

            Otherwise, enter SYN-RECEIVED, form a SYN,ACK segment
            <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>

            and send it. Set the variables:

            SND.WND <- SEG.WND
            SND.WL1 <- SEG.SEQ SND.WL2 <- SEG.ACK If there are other controls or text in the segment, queue them for processing after the ESTABLISHED state has been reached, return.
            Note that it is legal to send and receive application data on SYN segments (this is the "text in the segment" mentioned above). There has been significant misinformation and misunderstanding of this topic historically. Some firewalls and security devices consider this suspicious. However, the capability was used in T/TCP [21] and is used in TCP Fast Open (TFO) [48], so is important for implementations and network devices to permit.

            Fifth, if neither of the SYN or RST bits is set, then drop the segment and return.
            */
            if tcph.ack() {
                if is_between_wrapped(
                    self.snd.una,
                    tcph.acknowledgment_number(),
                    self.snd.nxt.wrapping_add(1),
                ) {
                    if tcph.rst() {
                        return Action::Reset;
                    }
                } else {
                    write_reset(&ip4h, &tcph, &[], tun);

                    return Action::Noop;
                }
            }

            if tcph.syn() {
                self.rcv.nxt = tcph.sequence_number().wrapping_add(1);
                self.rcv.irs = tcph.sequence_number();
                self.snd.una = tcph.acknowledgment_number();

                // Our syn is acked
                if wrapping_lt(self.snd.iss, self.snd.una) {
                    self.snd.wnd = tcph.window_size();
                    self.snd.wl1 = tcph.sequence_number();
                    self.snd.wl2 = tcph.acknowledgment_number();

                    if self.snd.wnd > self.snd.max_wnd {
                        self.snd.max_wnd = self.snd.wnd;
                    }

                    self.outgoing.reserve_exact(self.snd.wnd as usize);
                    self.incoming.reserve_exact(64240);

                    // Pop the syn segment and turn off its timer
                    self.segments.pop_front().unwrap();
                    assert!(self.segments.is_empty());

                    self.timeout.take();

                    println!("\t\tState <- Estab");
                    self.state = State::Estab;

                    write_ack(&self.quad, self.snd.nxt, self.rcv.nxt, self.snd.wnd, tun);

                    return Action::IsEstablished;
                } else {
                    println!("\t\tState <- SynRcvd");
                    self.state = State::SynRcvd;

                    write_synack(&self.quad, self.snd.nxt, self.rcv.nxt, self.snd.wnd, tun);

                    return Action::Noop;
                }
            }

            return Action::Noop;
        } else {
            /*
            Otherwise,
                First, check sequence number:
                -   SYN-RECEIVED STATE
                -   ESTABLISHED STATE
                -   FIN-WAIT-1 STATE
                -   FIN-WAIT-2 STATE
                -   CLOSE-WAIT STATE
                -   CLOSING STATE
                -   LAST-ACK STATE
                -   TIME-WAIT STATE
            */
            let seg_len =
                data.len() + if tcph.ack() { 1 } else { 0 } + if tcph.fin() { 1 } else { 0 };

            // If an incoming segment is not acceptable, an acknowledgment
            // should be sent in reply (unless the RST bit is set, if so
            // drop the segment and return)
            if !self.is_segment_valid(&tcph, seg_len as u32) {
                if tcph.rst() {
                    return Action::Noop;
                }

                println!("\t\tSegment invalid");
                write_ack(&self.quad, self.snd.nxt, self.rcv.nxt, self.rcv.wnd, tun);

                // After sending the acknowledgment, drop the unacceptable
                // segment and return.
                return Action::Noop;
            }

            // Second, check the RST bit
            if tcph.rst() {
                if self.state == State::SynRcvd {
                    /*
                    SYN-RECEIVED STATE
                        If the RST bit is set,
                            If this connection was initiated with a passive OPEN
                            (i.e., came from the LISTEN state), then return this
                            connection to LISTEN state and return. The user need not
                            be informed. If this connection was initiated with an
                            active OPEN (i.e., came from SYN-SENT state), then the
                            connection was refused; signal the user "connection
                            refused". In either case, the retransmission queue should
                            be flushed. And in the active OPEN case, enter the CLOSED
                            state and delete the TCB, and return.
                    */

                    if self.kind == Kind::Passive {
                        return Action::RemoveFromPending;
                    } else {
                        return Action::ConnectionRefused;
                    }
                } else if self.state == State::Estab
                    || self.state == State::FinWait1
                    || self.state == State::FinWait2
                    || self.state == State::CloseWait
                {
                    /*
                    ESTABLISHED STATE
                    FIN-WAIT-1 STATE
                    FIN-WAIT-2 STATE
                    CLOSE-WAIT STATE
                        If the RST bit is set, then any outstanding RECEIVEs and
                        SEND should receive "reset" responses. All segment queues
                        should be flushed. Users should also receive an unsolicited
                        general "connection reset" signal. Enter the CLOSED state,
                        delete the TCB, and return.
                    */

                    self.reset.store(true, Ordering::Release);
                    return Action::Reset;
                }
            }

            // Fourth, check the SYN bit:
            if tcph.syn() {
                if self.state == State::SynRcvd {
                    /*
                    SYN-RECEIVED STATE
                        If the connection was initiated with a passive OPEN, then
                        return this connection to the LISTEN state and return.
                        Otherwise, handle per the directions for synchronized states
                        below.
                    */

                    if self.kind == Kind::Passive {
                        return Action::RemoveFromPending;
                    }
                } else if self.state == State::Estab
                    || self.state == State::FinWait1
                    || self.state == State::FinWait2
                    || self.state == State::CloseWait
                    || self.state == State::Closing
                    || self.state == State::LastAck
                    || self.state == State::TimeWait
                {
                    /*
                    ESTABLISHED STATE
                    FIN-WAIT-1 STATE
                    FIN-WAIT-2 STATE
                    CLOSE-WAIT STATE
                    CLOSING STATE
                    LAST-ACK STATE
                    TIME-WAIT STATE
                    -   If the SYN bit is set in these synchronized states, it may
                        be either a legitimate new connection attempt (e.g., in the
                        case of TIME-WAIT), an error where the connection should be
                        reset, or the result of an attack attempt, as described in
                        RFC 5961 [9]. For the TIME-WAIT state, new connections can
                        be accepted if the Timestamp Option is used and meets
                        expectations (per [40]). For all other cases, RFC 5961
                        provides a mitigation with applicability to some situations,
                        though there are also alternatives that offer cryptographic
                        protection (see Section 7). RFC 5961 recommends that in
                        these synchronized states, if the SYN bit is set,
                        irrespective of the sequence number, TCP endpoints MUST send
                        a "challenge ACK" to the remote peer:

                            <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>

                    -   After sending the acknowledgment, TCP implementations MUST
                        drop the unacceptable segment and stop processing further.
                        Note that RFC 5961 and Errata ID 4772 [99] contain
                        additional ACK throttling notes for an implementation.

                    -   For implementations that do not follow RFC 5961, the
                        original behavior described in RFC 793 follows in this
                        paragraph. If the SYN is in the window it is an error: send
                        a reset, any outstanding RECEIVEs and SEND should receive
                        "reset" responses, all segment queues should be flushed, the
                        user should also receive an unsolicited general "connection
                        reset" signal, enter the CLOSED state, delete the TCB, and
                        return.

                    -   If the SYN is not in the window, this step would not be
                        reached and an ACK would have been sent in the first step
                        (sequence number check).
                    */

                    // For now we don't implement RFC 5961 so we just send a reset.
                    write_reset(&ip4h, &tcph, data, tun);

                    return Action::Reset;
                }
            }

            // Fifth, check the ACK field:
            // -    if the ACK bit is off, drop the segment and return
            if !tcph.ack() {
                return Action::Noop;
            }

            let mut wake_up_reader = false;
            let mut wake_up_writer = false;
            let mut wake_up_closer = false;

            if self.state == State::SynRcvd {
                /*
                SYN-RECEIVED STATE
                    -   If SND.UNA < SEG.ACK =< SND.NXT, then enter ESTABLISHED
                        state and continue processing with the variables below
                        set to:

                            SND.WND <- SEG.WND
                            SND.WL1 <- SEG.SEQ
                            SND.WL2 <- SEG.ACK

                    -   If the segment acknowledgment is not acceptable, form a reset segment

                            <SEQ=SEG.ACK><CTL=RST>

                        and send it.
                */
                if is_between_wrapped(
                    self.snd.una,
                    tcph.acknowledgment_number(),
                    self.snd.nxt.wrapping_add(1),
                ) {
                    println!("\t\tState <- Estab");
                    self.state = State::Estab;

                    self.snd.wnd = tcph.window_size();
                    self.snd.wl1 = tcph.sequence_number();
                    self.snd.wl2 = tcph.acknowledgment_number();

                    if self.snd.wnd > self.snd.max_wnd {
                        self.snd.max_wnd = self.snd.wnd;
                    }

                    self.outgoing.reserve_exact(self.snd.wnd as usize);
                    self.incoming.reserve_exact(64240);

                    // Pop the syn segment and turn off its timer
                    self.segments.pop_front().unwrap();
                    assert!(self.segments.is_empty());

                    self.timeout.take();

                    return Action::IsEstablished;
                } else {
                    write_reset(&ip4h, &tcph, data, tun);

                    return Action::Noop;
                }
            } else if self.state == State::Estab
                || self.state == State::FinWait1
                || self.state == State::FinWait2
                || self.state == State::CloseWait
                || self.state == State::Closing
            {
                /*
                ESTABLISHED STATE
                -   If SND.UNA < SEG.ACK =< SND.NXT, then set SND.UNA <- SEG.ACK.
                    Any segments on the retransmission queue that
                    are thereby entirely acknowledged are removed. Users
                    should receive positive acknowledgments for buffers that
                    have been SENT and fully acknowledged (i.e., SEND buffer
                    should be returned with "ok" response). If the ACK is a
                    duplicate (SEG.ACK =< SND.UNA), it can be ignored. If the
                    ACK acks something not yet sent (SEG.ACK > SND.NXT), then
                    send an ACK, drop the segment, and return.

                -   If SND.UNA =< SEG.ACK =< SND.NXT, the send window should
                    be updated. If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ
                    and SND.WL2 =< SEG.ACK)), set SND.WND <- SEG.WND, set
                    SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK.

                -   Note that SND.WND is an offset from SND.UNA, that SND.WL1
                    records the sequence number of the last segment used to
                    update SND.WND, and that SND.WL2 records the
                    acknowledgment number of the last segment used to update
                    SND.WND. The check here prevents using old segments to
                    update the window.
                */

                if is_between_wrapped(
                    self.snd.una,
                    tcph.acknowledgment_number(),
                    self.snd.nxt.wrapping_add(1),
                ) {
                    self.congestion_control();

                    let (can_write, r) = self.process_ack(tcph.acknowledgment_number());

                    if let Some(r) = r {
                        self.compute_rto(r);
                    }

                    wake_up_writer = can_write;
                } else if wrapping_lt(self.snd.nxt, tcph.acknowledgment_number()) {
                    println!("\t\tInvalid Ack");
                    write_ack(&self.quad, self.snd.nxt, self.rcv.nxt, self.rcv.wnd, tun);

                    return Action::Noop;
                }

                if is_between_wrapped(
                    self.snd.una.wrapping_sub(1),
                    tcph.acknowledgment_number(),
                    self.snd.nxt.wrapping_add(1),
                ) {
                    if wrapping_lt(self.snd.wl1, tcph.sequence_number())
                        || (self.snd.wl1 == tcph.sequence_number()
                            && wrapping_lt(self.snd.wl2, tcph.sequence_number().wrapping_add(1)))
                    {
                        self.snd.wnd = tcph.window_size();
                        self.snd.wl1 = tcph.sequence_number();
                        self.snd.wl2 = tcph.acknowledgment_number();

                        if self.snd.wnd > self.snd.max_wnd {
                            self.snd.wnd = self.snd.max_wnd;
                        }

                        if self.snd.wnd == 0 {
                            self.probe_timeout =
                                Some(Instant::now() + Duration::from_millis(self.rto as u64));
                        } else {
                            self.probe_timeout.take();
                        }
                    }
                }
            } else if self.state == State::LastAck {
                /*
                The only thing that can arrive in this state is an
                acknowledgment of our FIN. If our FIN is now
                acknowledged, delete the TCB, enter the CLOSED state,
                and return
                */

                self.process_ack(tcph.acknowledgment_number());

                if self.is_fin_acked() {
                    return Action::DeleteTCB;
                }
            } else if self.state == State::TimeWait {
                /*
                The only thing that can arrive in this state is a
                retransmission of the remote FIN. Acknowledge it, and
                restart the 2 MSL timeout.
                */

                self.time_wait = Some(Instant::now() + Duration::from_secs(2 * 2 * 60));

                println!("\tAck retransmitted fin");
                write_ack(&self.quad, self.snd.nxt, self.rcv.nxt, self.rcv.wnd, tun);
            }

            /*
            In addition to the processing for the ESTABLISHED state,
            if the FIN segment is now acknowledged, then enter FIN-
            WAIT-2 and continue processing in that state.
            */
            if self.state == State::FinWait1 {
                if self.is_fin_acked() {
                    println!("\t\tState <- FinWait2");
                    self.state = State::FinWait2;
                }
            }

            /*
            In addition to the processing for the ESTABLISHED state,
            if the retransmission queue is empty, the user's CLOSE
            can be acknowledged ("ok") but do not delete the TCB.
            */
            if self.state == State::FinWait2 {
                /*
                Our FIN has been acked so there are no other segment
                to be retransmitted.
                */

                wake_up_closer = true;
            }

            let mut process_fin = tcph.fin();

            // Seventh, process the segment text:
            if self.state == State::Estab
                || self.state == State::FinWait1
                || self.state == State::FinWait2
            {
                println!("\tProcess segment data");
                /*
                ESTABLISHED STATE
                FIN-WAIT-1 STATE
                FIN-WAIT-2 STATE
                -   Once in the ESTABLISHED state, it is possible to deliver
                    segment data to user RECEIVE buffers. Data from segments can
                    be moved into buffers until either the buffer is full or the
                    segment is empty. If the segment empties and carries a PUSH
                    flag, then the user is informed, when the buffer is
                    returned, that a PUSH has been received.

                -   When the TCP endpoint takes responsibility for delivering
                    the data to the user, it must also acknowledge the receipt
                    of the data.

                -   Once the TCP endpoint takes responsibility for the data, it
                    advances RCV.NXT over the data accepted, and adjusts RCV.WND
                    as appropriate to the current buffer availability. The total
                    of RCV.NXT and RCV.WND should not be reduced.

                -   A TCP implementation MAY send an ACK segment acknowledging
                    RCV.NXT when a valid segment arrives that is in the window
                    but not at the left window edge (MAY-13).

                -   Please note the window management suggestions in Section 3.8.

                -   Send an acknowledgment of the form:

                    <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>

                -   This acknowledgment should be piggybacked on a segment being
                    transmitted if possible without incurring undue delay.
                */

                let new = (self.rcv.nxt.wrapping_sub(tcph.sequence_number())) as usize;
                let new_len = data.len() - new;
                let acc_len = cmp::min(new_len, self.rcv.wnd as usize);

                let data = &data[new..new + acc_len];

                process_fin &= new_len == acc_len;

                self.incoming.extend(data.iter());

                let pre_nxt = self.rcv.nxt;
                self.rcv.nxt = self
                    .rcv
                    .nxt
                    .wrapping_add(acc_len as u32)
                    .wrapping_add(if process_fin { 1 } else { 0 });

                let pre_wnd = self.rcv.wnd;
                self.rcv.wnd = self.rcv.wnd - acc_len as u16;

                // Only ack if accepted new data, or the window was zero and this is a probe segment
                if wrapping_lt(pre_nxt, self.rcv.nxt) || pre_wnd == 0 {
                    println!("\tAck data");
                    write_ack(&self.quad, self.snd.nxt, self.rcv.nxt, self.rcv.wnd, tun);
                }

                wake_up_reader = !data.is_empty();
            } else if self.state == State::CloseWait
                || self.state == State::Closing
                || self.state == State::LastAck
                || self.state == State::TimeWait
            {
                /*
                CLOSE-WAIT STATE
                CLOSING STATE
                LAST-ACK STATE
                TIME-WAIT STATE

                -   This should not occur since a FIN has been received from the
                    remote side. Ignore the segment text.
                */
            }

            /*
            Eighth, check the FIN bit:
            -   Do not process the FIN if the state is CLOSED, LISTEN, or SYN-
                SENT since the SEG.SEQ cannot be validated; drop the segment
                and return.

            -   If the FIN bit is set, signal the user "connection closing" and
                return any pending RECEIVEs with same message, advance RCV.NXT
                over the FIN, and send an acknowledgment for the FIN. Note that
                FIN implies PUSH for any segment text not yet delivered to the
                user.

                SYN-RECEIVED STATE
                ESTABLISHED STATE
                Enter the CLOSE-WAIT state.

                FIN-WAIT-1 STATE
                If our FIN has been ACKed (perhaps in this segment), then
                enter TIME-WAIT, start the time-wait timer, turn off the
                other timers; otherwise, enter the CLOSING state.

                FIN-WAIT-2 STATE
                Enter the TIME-WAIT state. Start the time-wait timer,
                turn off the other timers.

                CLOSE-WAIT STATE
                Remain in the CLOSE-WAIT state.

                CLOSING STATE
                Remain in the CLOSING state.

                LAST-ACK STATE
                Remain in the LAST-ACK state.

                TIME-WAIT STATE
                Remain in the TIME-WAIT state. Restart the 2 MSL time-
                wait timeout.

                and return.
            */
            if process_fin {
                println!("\t\tProcessing FIN");
                if self.state == State::Listen || self.state == State::SynSent {
                    return Action::Noop;
                } else if self.state == State::SynRcvd || self.state == State::Estab {
                    println!("\t\tState <- CloseWait");
                    self.state = State::CloseWait;
                    self.read_closed.store(true, Ordering::Release);
                    wake_up_reader = true;
                } else if self.state == State::FinWait1 {
                    if self.is_fin_acked() {
                        println!("\t\tState <- TimeWait");
                        self.state = State::TimeWait;
                        self.timeout = None;
                        self.time_wait = Some(Instant::now() + Duration::from_secs(2 * 2 * 60));
                    } else {
                        println!("\t\tState <- Closing");
                        self.state = State::Closing;
                    }
                } else if self.state == State::FinWait2 {
                    println!("\t\tState <- TimeWait");
                    self.state = State::TimeWait;
                    self.timeout = None;
                    self.time_wait = Some(Instant::now() + Duration::from_secs(2 * 2 * 60));
                } else if self.state == State::CloseWait
                    || self.state == State::Closing
                    || self.state == State::LastAck
                {
                    return Action::Noop;
                } else if self.state == State::TimeWait {
                    self.time_wait = Some(Instant::now() + Duration::from_secs(2 * 2 * 60));
                }
            }

            return Action::Wakeup {
                wake_up_reader,
                wake_up_writer,
                wake_up_closer,
            };
        }
    }

    /*
    There are four cases for the acceptability test for an
    incoming segment:

    Segment Length 	Receive Window 	Test
    0 	            0 	            SEG.SEQ = RCV.NXT

    0 	            >0 	            RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND

    >0 	            0 	            not acceptable

                                    RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND

    >0 	            >0              or

                                    RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
    */
    fn is_segment_valid(&self, tcph: &TcpHeaderSlice, seg_len: u32) -> bool {
        let seg_seq = tcph.sequence_number();
        let rcv_wnd = self.rcv.wnd as u32;
        let rcv_nxt = self.rcv.nxt;

        if seg_len == 0 && rcv_wnd == 0 {
            seg_seq == rcv_nxt
        } else if seg_len == 0 && rcv_wnd > 0 {
            is_between_wrapped(
                rcv_nxt.wrapping_sub(1),
                seg_seq,
                rcv_nxt.wrapping_add(rcv_wnd),
            )
        } else if seg_len > 0 && rcv_wnd == 0 {
            false
        } else if seg_len > 0 && rcv_wnd > 0 {
            is_between_wrapped(
                rcv_nxt.wrapping_sub(1),
                seg_seq,
                rcv_nxt.wrapping_add(rcv_wnd),
            ) || is_between_wrapped(
                rcv_nxt.wrapping_sub(1),
                seg_seq.wrapping_add(seg_len).wrapping_sub(1),
                rcv_nxt.wrapping_add(rcv_wnd),
            )
        } else {
            false
        }
    }
}

fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    // From RFC1323:
    //     TCP determines if a data segment is "old" or "new" by testing
    //     whether its sequence number is within 2**31 bytes of the left edge
    //     of the window, and if it is not, discarding the data as "old".  To
    //     insure that new data is never mistakenly considered old and vice-
    //     versa, the left edge of the sender's window has to be at most
    //     2**31 away from the right edge of the receiver's window.
    lhs.wrapping_sub(rhs) > (1 << 31)
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    wrapping_lt(start, x) && wrapping_lt(x, end)
}
