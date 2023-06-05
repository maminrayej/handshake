use std::io::{Read, Write};
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

    println!(">>> Trying to connect to server...");
    let mut stream = netstack
        .connect("127.0.0.1".parse::<Ipv4Addr>().unwrap(), 34343)
        .unwrap();
    println!(">>> Connected!");

    loop {
        let mut buf = [0u8; 1500];
        let n = stream.read(&mut buf[..]).unwrap();

        if n == 0 {
            break;
        }

        stream.write(&buf[..n]).unwrap();

        println!(
            "\n>>> Read: {:?}\n",
            String::from_iter(buf[..n].iter().map(|c| *c as char))
        );
    }

    drop(stream);

    netstack.join();
}
