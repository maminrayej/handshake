use std::net::Ipv4Addr;
use std::str::FromStr;

use handshake::NetStack;

fn main() {
    let mut netstack = NetStack::new(
        "tun0",
        Ipv4Addr::from_str("10.10.10.10").unwrap(),
        Ipv4Addr::from_str("255.255.255.0").unwrap(),
    )
    .unwrap();

    let listener = netstack.bind(9090).unwrap();

    let stream = listener.accept();

    println!("{stream:?}");

    netstack.join();
}
