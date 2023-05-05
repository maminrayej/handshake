use std::io::{Cursor, Write};

use etherparse::{Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};
use tidy_tuntap::Tun;

use super::Quad;

fn write(ip4h: &Ipv4Header, tcph: &TcpHeader, data: &[u8], tun: &mut Tun) {
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

pub fn write_synack(
    ip4h: &Ipv4HeaderSlice,
    tcph: &TcpHeaderSlice,
    iss: u32,
    ackno: u32,
    wnd: u16,
    tun: &mut Tun,
) {
    let mut tcph = TcpHeader::new(tcph.destination_port(), tcph.source_port(), iss, 1024);

    let ip4h = Ipv4Header::new(tcph.header_len(), 32, 6, ip4h.destination(), ip4h.source());

    tcph.syn = true;
    tcph.ack = true;
    tcph.acknowledgment_number = ackno;
    tcph.window_size = wnd;
    tcph.checksum = tcph.calc_checksum_ipv4(&ip4h, &[]).unwrap();

    write(&ip4h, &tcph, &[], tun);
}

pub fn write_ack(
    ip4h: &Ipv4HeaderSlice,
    tcph: &TcpHeaderSlice,
    sqno: u32,
    ackno: u32,
    wnd: u16,
    tun: &mut Tun,
) {
    let mut tcph = TcpHeader::new(tcph.destination_port(), tcph.source_port(), sqno, 1024);

    let ip4h = Ipv4Header::new(tcph.header_len(), 32, 6, ip4h.destination(), ip4h.source());

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
) {
    let mut tcph = TcpHeader::new(quad.dst.port, quad.src.port, sqno, 1024);

    let ip4h = Ipv4Header::new(
        tcph.header_len(),
        32,
        6,
        quad.dst.ipv4.octets(),
        quad.src.ipv4.octets(),
    );

    tcph.ack = true;
    tcph.acknowledgment_number = ackno;
    tcph.window_size = wnd;
    tcph.fin = fin;
    tcph.checksum = tcph.calc_checksum_ipv4(&ip4h, &[]).unwrap();

    write(&ip4h, &tcph, data, tun);
}
