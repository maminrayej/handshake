use std::io::{Cursor, Write};

use etherparse::{Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice, TcpOptionElement};
use tidy_tuntap::Tun;

use super::Quad;

// const FAIL_PROB: f64 = 0.5;

fn write(ip4h: &Ipv4Header, tcph: &TcpHeader, data: &[u8], tun: &mut Tun) {
    // // Drop the segment randomly
    // if rand::random::<f64>() < FAIL_PROB {
    //     println!("\t\t\t!!!Segment is dropped!!!");

    //     return;
    // }

    let mut cursor = Cursor::new([0u8; 1500]);
    ip4h.write(&mut cursor).unwrap();
    tcph.write(&mut cursor).unwrap();
    cursor.write(data).unwrap();

    let buf = cursor.get_ref();
    let pos = cursor.position() as usize;

    tun.write(&buf[..pos]).unwrap();
}

pub fn write_reset(ip4h: &Ipv4HeaderSlice, tcph: &TcpHeaderSlice, data: &[u8], tun: &mut Tun) {
    let sqno = if tcph.ack() {
        tcph.acknowledgment_number()
    } else {
        0
    };

    let ackno = tcph.sequence_number() + data.len() as u32 + if tcph.syn() { 1 } else { 0 };

    let mut tcph = TcpHeader::new(tcph.destination_port(), tcph.source_port(), sqno, 1024);

    let ip4h = Ipv4Header::new(tcph.header_len(), 32, 6, ip4h.destination(), ip4h.source());

    tcph.ack = true;
    tcph.rst = true;
    tcph.acknowledgment_number = ackno;
    tcph.checksum = tcph.calc_checksum_ipv4(&ip4h, &[]).unwrap();

    write(&ip4h, &tcph, &[], tun);
}

pub fn write_synack(quad: &Quad, sqno: u32, ackno: u32, wnd: u16, tun: &mut Tun) {
    let mut tcph = TcpHeader::new(quad.src.port, quad.dst.port, sqno, 1024);

    let ip4h = Ipv4Header::new(
        tcph.header_len(),
        32,
        6,
        quad.src.ipv4.octets(),
        quad.dst.ipv4.octets(),
    );

    tcph.ack = true;
    tcph.syn = true;
    tcph.acknowledgment_number = ackno;
    tcph.window_size = wnd;
    tcph.checksum = tcph.calc_checksum_ipv4(&ip4h, &[]).unwrap();

    write(&ip4h, &tcph, &[], tun);
}

pub fn write_ack(quad: &Quad, sqno: u32, ackno: u32, wnd: u16, tun: &mut Tun) {
    let mut tcph = TcpHeader::new(quad.src.port, quad.dst.port, sqno, 1024);

    let ip4h = Ipv4Header::new(
        tcph.header_len(),
        32,
        6,
        quad.src.ipv4.octets(),
        quad.dst.ipv4.octets(),
    );

    tcph.ack = true;
    tcph.acknowledgment_number = ackno;
    tcph.window_size = wnd;
    tcph.checksum = tcph.calc_checksum_ipv4(&ip4h, &[]).unwrap();

    write(&ip4h, &tcph, &[], tun);
}

pub fn write_data(
    quad: Quad,
    sqno: u32,
    ackno: u32,
    wnd: u16,
    tun: &mut Tun,
    data: &[u8],
    fin: bool,
    syn: bool,
    ack: bool,
    mss: Option<u16>,
) {
    let mut tcph = TcpHeader::new(quad.src.port, quad.dst.port, sqno, wnd);

    if let Some(mss) = mss {
        tcph.set_options(&[TcpOptionElement::MaximumSegmentSize(mss)])
            .unwrap();
    }

    let ip4h = Ipv4Header::new(
        tcph.header_len() + data.len() as u16,
        32,
        6,
        quad.src.ipv4.octets(),
        quad.dst.ipv4.octets(),
    );

    tcph.ack = ack;
    tcph.acknowledgment_number = ackno;
    tcph.window_size = wnd;
    tcph.fin = fin;
    tcph.syn = syn;
    tcph.checksum = tcph.calc_checksum_ipv4(&ip4h, data).unwrap();

    write(&ip4h, &tcph, data, tun);
}
