use std::io::Read;
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

    println!(">>> Waiting for incoming connections...");
    let mut stream = listener.accept().unwrap();
    println!(">>> Connection accepted");

    let mut total = 0;
    loop {
        if total >= 2 {
            break;
        }

        let mut buf = [0u8; 1500];
        let n = stream.read(&mut buf[..]).unwrap();

        total += n;

        println!(
            "\n>>> Read: {:?}\n",
            String::from_iter(buf[..n].iter().map(|c| *c as char))
        );
    }

    drop(stream);

    netstack.join();
}
