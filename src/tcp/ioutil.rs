use std::io::Cursor;

use etherparse::{Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};

pub fn generate_reset(
    ip4h: &Ipv4HeaderSlice,
    tcph: &TcpHeaderSlice,
    data: &[u8],
) -> Cursor<[u8; 1500]> {
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

    let mut cursor = Cursor::new([0u8; 1500]);
    ip4h.write(&mut cursor).unwrap();
    tcph.write(&mut cursor).unwrap();

    cursor
}

pub fn generate_synack(
    ip4h: &Ipv4HeaderSlice,
    tcph: &TcpHeaderSlice,
    iss: u32,
    ackno: u32,
) -> Cursor<[u8; 1500]> {
    let mut tcph = TcpHeader::new(tcph.destination_port(), tcph.source_port(), iss, 1024);

    let ip4h = Ipv4Header::new(tcph.header_len(), 32, 6, ip4h.destination(), ip4h.source());

    tcph.syn = true;
    tcph.ack = true;
    tcph.acknowledgment_number = ackno;
    tcph.checksum = tcph.calc_checksum_ipv4(&ip4h, &[]).unwrap();

    let mut cursor = Cursor::new([0u8; 1500]);
    ip4h.write(&mut cursor).unwrap();
    tcph.write(&mut cursor).unwrap();

    cursor
}
