use std::cmp;
use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};

mod ioutil;
mod listen;
mod stream;

pub use ioutil::*;
pub use listen::*;
pub use stream::*;
use tidy_tuntap::Tun;

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Active,
    Passive,
}

// TODO: Add support for combination of actions to be returned
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Noop,
    AddToPending(TCB),
    RemoveFromPending,
    IsEstablished,
    Reset,
    WakeUpReader,
    DeleteTCB,
    WakeUpWriter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    sno: u32,
    una: u32,
    len: u32,
    fin: bool,

    retry: bool,
    sent: Instant,
}

impl Segment {
    fn end(&self) -> u32 {
        self.sno + self.len - 1
    }

    fn unacked_len(&self) -> usize {
        (self.end().wrapping_sub(self.una) + 1) as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TCB {
    pub(crate) quad: Quad,
    pub(crate) kind: Kind,
    pub(crate) state: State,
    pub(crate) reset: bool,
    pub(crate) closed: bool,
    pub(crate) time_wait: Option<Instant>,

    pub(crate) snd: SendSpace,
    pub(crate) rcv: RecvSpace,

    pub(crate) srtt: u128,
    pub(crate) rttvar: u128,
    pub(crate) rto: u128,
    pub(crate) rtt_measured: bool,
    pub(crate) timeout: Option<Instant>,

    pub(crate) cwnd: u32,
    pub(crate) rwnd: u32,
    pub(crate) ssthresh: u32,

    pub(crate) incoming: VecDeque<u8>,
    pub(crate) outgoing: VecDeque<u8>,
    pub(crate) segments: VecDeque<Segment>,
}

impl TCB {
    pub fn listen(quad: Quad) -> Self {
        // TODO: Choose a random initial sequence number
        let iss = 0;

        let buf = VecDeque::with_capacity(64240);

        TCB {
            quad,
            kind: Kind::Passive,
            state: State::Listen,
            reset: false,
            closed: false,
            time_wait: None,
            snd: SendSpace {
                una: iss,
                nxt: iss,
                wnd: 0,
                urp: 0,
                wl1: 0,
                wl2: 0,
                iss,
            },
            rcv: RecvSpace {
                nxt: 0,
                wnd: buf.capacity() as u16,
                urp: 0,
                irs: 0,
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
            rwnd: 0, // TODO: update rwnd when receiving new segments
            /*
            The initial value of ssthresh SHOULD be set arbitrarily high (e.g.,
            to the size of the largest possible advertised window), but ssthresh
            MUST be reduced in response to congestion.  Setting ssthresh as high
            as possible allows the network conditions, rather than some arbitrary
            host limit, to dictate the sending rate.
            */
            ssthresh: u32::MAX,
            incoming: buf,
            outgoing: VecDeque::new(),
            segments: VecDeque::new(),
        }
    }

    pub fn is_slow_start(&self) -> bool {
        self.cwnd > self.ssthresh
    }

    pub fn is_outgoing_full(&self) -> bool {
        self.outgoing.capacity() == self.outgoing.len()
    }

    pub fn close(&mut self) {
        self.closed = true;

        self.state = State::FinWait1;

        let sent_len = self.snd.nxt.wrapping_sub(self.snd.una) as usize;
        let available_len = self.outgoing.len() - sent_len;

        if available_len == 0 {
            let fin = Segment {
                sno: self.snd.nxt,
                una: self.snd.nxt,
                len: 0,
                fin: true,
                retry: false,
                sent: Instant::now(),
            };

            self.segments.push_back(fin);

            self.snd.nxt = self.snd.nxt.wrapping_add(1);
        }
    }

    pub fn on_tick(&mut self, tun: &mut Tun) -> Action {
        if let Some(timeout) = self.time_wait.clone() {
            if Instant::now() >= timeout {
                let seg = self.segments.front_mut().unwrap();

                let data: Vec<u8> = self
                    .outgoing
                    .iter()
                    .cloned()
                    .take(seg.unacked_len())
                    .collect();

                write_data(
                    self.quad,
                    seg.sno,
                    self.rcv.nxt,
                    self.rcv.wnd,
                    tun,
                    &data[..],
                    seg.fin,
                );

                seg.retry = true;
                seg.sent = Instant::now();

                self.rto *= 2;
                self.timeout = Some(seg.sent + Duration::from_millis(self.rto as u64));
            }
        } else if !self.outgoing.is_empty() {
            let sent_len = self.snd.nxt.wrapping_sub(self.snd.una) as usize;
            let available_len = self.outgoing.len() - sent_len;

            if available_len > 0 {
                let data_len = cmp::min(available_len, 536);
                let fin = data_len == available_len && self.closed;

                let data: Vec<u8> = self
                    .outgoing
                    .iter()
                    .copied()
                    .skip(sent_len)
                    .take(data_len)
                    .collect();

                write_data(
                    self.quad,
                    self.snd.nxt,
                    self.rcv.nxt,
                    self.rcv.wnd,
                    tun,
                    data.as_slice(),
                    fin,
                );

                let seg = Segment {
                    sno: self.snd.nxt,
                    una: self.snd.nxt,
                    len: data_len as u32,
                    fin,
                    retry: false,
                    sent: Instant::now(),
                };

                self.segments.push_back(seg);

                self.snd.nxt = self
                    .snd
                    .nxt
                    .wrapping_add(data_len as u32)
                    .wrapping_add(if fin { 1 } else { 0 });
            }
        } else if !self.segments.is_empty() {
            let seg = self.segments.pop_front().unwrap();

            assert!(self.segments.is_empty());
            assert_eq!(seg.len, 0);
            assert!(seg.fin);

            write_data(
                self.quad,
                seg.sno,
                self.rcv.nxt,
                self.rcv.wnd,
                tun,
                &[],
                seg.fin,
            );
        } else if let Some(time_wait) = self.time_wait.clone() {
            if time_wait >= Instant::now() {
                return Action::DeleteTCB;
            }
        }

        Action::Noop
    }

    pub fn on_segment(
        &mut self,
        ip4h: Ipv4HeaderSlice,
        tcph: TcpHeaderSlice,
        data: &[u8],
        tun: &mut Tun,
    ) -> Action {
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
                self.rcv.nxt = tcph.sequence_number().wrapping_add(1);
                self.rcv.irs = tcph.sequence_number();

                self.snd.wnd = tcph.window_size();
                self.snd.nxt = self.snd.iss.wrapping_add(1);

                self.outgoing.reserve(self.snd.wnd as usize);

                self.state = State::SynRcvd;

                write_synack(&ip4h, &tcph, self.snd.iss, self.rcv.nxt, self.rcv.wnd, tun);

                return Action::AddToPending(self.clone());
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

                write_ack(&ip4h, &tcph, self.snd.nxt, self.rcv.nxt, self.rcv.wnd, tun);

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
                        // TODO: Inform the user that connection has been refused.
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

                    self.reset = true;
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

                    // TODO: For now we don't implement RFC 5961 so we just send a reset.
                    write_reset(&ip4h, &tcph, data, tun);

                    return Action::Reset;
                }
            }

            // Fifth, check the ACK field:
            // -    if the ACK bit is off, drop the segment and return
            if !tcph.ack() {
                return Action::Noop;
            }

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
                    self.state = State::Estab;

                    self.snd.wnd = tcph.window_size();
                    self.snd.wl1 = tcph.sequence_number();
                    self.snd.wl2 = tcph.acknowledgment_number();

                    return Action::IsEstablished;
                } else {
                    write_reset(&ip4h, &tcph, data, tun);
                }
            } else if self.state == State::Estab
                || self.state == State::FinWait1
                || self.state == State::FinWait2
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
                    self.snd.una = tcph.acknowledgment_number();

                    if self.is_slow_start() {
                        /*
                        During slow start, a TCP increments cwnd by at most SMSS bytes for
                        each ACK received that cumulatively acknowledges new data.
                        */
                        self.cwnd += 536;
                    } else {
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
                        self.cwnd += cmp::max(((536 * 536) as f64 / self.cwnd as f64) as u32, 1);
                    }

                    let mut compute_rto = false;
                    let mut r = 0;
                    while !self.segments.is_empty() {
                        let seg = self.segments.front_mut().unwrap();
                        let end = seg.end();
                        let ackno = tcph.acknowledgment_number();

                        compute_rto = seg.retry == false;
                        r = (Instant::now() - seg.sent).as_millis();

                        if is_between_wrapped(seg.una, ackno, end.wrapping_add(1)) {
                            // Partial acknowledgment

                            let acked = ackno.wrapping_sub(seg.una);
                            self.outgoing.drain(..acked as usize);

                            seg.una = ackno;
                        } else if wrapping_lt(end, ackno) {
                            // Full acknowledgment

                            let seg = self.segments.pop_front().unwrap();
                            self.outgoing.drain(..seg.unacked_len());
                        }
                    }

                    if compute_rto {
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
                            self.rttvar = ((1.0 - 0.25) * self.rttvar as f64
                                + 0.25 * self.srtt.abs_diff(r) as f64)
                                as u128;
                            self.srtt =
                                ((1.0 - 0.125) * self.srtt as f64 + 0.125 * r as f64) as u128;
                        }

                        self.rto = self.srtt + cmp::max(100, 4 * self.rttvar);

                        /*
                        Whenever RTO is computed, if it is less than 1 second, then the
                        RTO SHOULD be rounded up to 1 second.
                        */
                        self.rto = cmp::min(self.rto, 1000);
                    }

                    if self.segments.is_empty() {
                        self.timeout = None;
                    } else {
                        let seg = self.segments.front().unwrap();

                        self.timeout = Some(seg.sent + Duration::from_millis(self.rto as u64));
                    }

                    return Action::WakeUpWriter;
                } else if wrapping_lt(self.snd.nxt, tcph.acknowledgment_number()) {
                    write_ack(&ip4h, &tcph, self.snd.nxt, self.rcv.nxt, self.rcv.wnd, tun);

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
                    }
                }
            }

            if self.state == State::FinWait1 {
                if self.outgoing.is_empty()
                    && self.segments.is_empty()
                    && self.snd.una == self.snd.nxt
                {
                    self.state = State::FinWait2;

                    // TODO: Wake up stream.close()
                }
            }

            // Seventh, process the segment text:
            if self.state == State::Estab
                || self.state == State::FinWait1
                || self.state == State::FinWait2
            {
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
                let len = data.len() - new;
                let len = cmp::min(len, self.rcv.wnd as usize);

                let data = &data[new..new + len];

                self.incoming.extend(data.iter());

                self.rcv.nxt = self.rcv.nxt.wrapping_add(len as u32);
                self.rcv.wnd = self.rcv.wnd - len as u16;

                write_ack(&ip4h, &tcph, self.snd.nxt, self.rcv.nxt, self.rcv.wnd, tun);

                return Action::WakeUpReader;
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
            if tcph.fin() {
                if self.state == State::Listen || self.state == State::SynSent {
                    return Action::Noop;
                }

                if self.state == State::SynRcvd || self.state == State::Estab {
                    self.state = State::CloseWait;
                }

                if self.state == State::FinWait1 {
                    todo!()
                }

                if self.state == State::FinWait2 {
                    self.state = State::TimeWait;
                    self.timeout = None;
                    self.time_wait = Some(Instant::now() + Duration::from_secs(2 * 2 * 60));
                }

                if self.state == State::CloseWait
                    || self.state == State::Closing
                    || self.state == State::LastAck
                {
                    return Action::Noop;
                }

                if self.state == State::TimeWait {
                    self.time_wait = Some(Instant::now() + Duration::from_secs(2 * 2 * 60));
                }
            }

            todo!("Some state combination is not implemented")
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
