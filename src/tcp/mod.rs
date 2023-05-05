use std::net::Ipv4Addr;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Noop,
    AddToPending(TCB),
    RemoveFromPending,
    IsEstablished,
    Reset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TCB {
    pub(crate) kind: Kind,
    pub(crate) state: State,
    pub(crate) reset: bool,

    pub(crate) snd: SendSpace,
    pub(crate) rcv: RecvSpace,
}

impl TCB {
    pub fn listen() -> Self {
        // TODO: Choose a random initial sequence number
        let iss = 0;

        TCB {
            kind: Kind::Passive,
            state: State::Listen,
            reset: false,
            snd: SendSpace {
                una: iss,
                nxt: iss,
                wnd: 1024,
                urp: 0,
                wl1: 0,
                wl2: 0,
                iss,
            },
            rcv: RecvSpace {
                nxt: 0,
                wnd: 0,
                urp: 0,
                irs: 0,
            },
        }
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
                self.rcv.nxt = tcph.sequence_number() + 1;
                self.rcv.irs = tcph.sequence_number();
                self.rcv.wnd = tcph.window_size();

                self.snd.nxt = self.snd.iss + 1;

                self.state = State::SynRcvd;

                write_synack(&ip4h, &tcph, self.snd.iss, self.rcv.nxt, tun);

                return Action::AddToPending(*self);
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

                write_ack(&ip4h, &tcph, self.snd.nxt, self.rcv.nxt, tun);

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
            } else if self.state == State::Estab {
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
                    // TODO: Remove acked buffers from retransmission queue
                } else if wrapping_lt(self.snd.nxt, tcph.acknowledgment_number()) {
                    write_ack(&ip4h, &tcph, self.snd.nxt, self.rcv.nxt, tun);

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
