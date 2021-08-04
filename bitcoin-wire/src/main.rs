extern crate bitcoin;

use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, process};
use std::io::Write;

use bitcoin::consensus::encode;
use bitcoin::network::{address, constants, message, message_network};
use bitcoin::network::stream_reader::StreamReader;


fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Too few args");
        process::exit(0);
    }
    let str_address = &args[1];

    let addr: SocketAddr = str_address.parse().unwrap_or_else(|_| {
        eprintln!("Error parsing address: {:?}", str_address);
        process::exit(1);
    });

    let version_message = build_version_message(addr);

    let first_message = message::RawNetworkMessage {
        magic: constants::Network::Bitcoin.magic(),
        payload: version_message,
    };

    if let Ok(mut stream) = TcpStream::connect(addr) {
        // Send a version message
        let _ = stream.write_all(encode::serialize(&first_message).as_slice());
        println!("Sent version message");

        // Setup StreamReader, a wrapper to the connection
        let read_stream = stream.try_clone().unwrap();
        let mut stream_reader = StreamReader::new(read_stream, None);
        loop {
            // Loop while there is a new message
            let reply = stream_reader.read_next();
            // Break in case of error
            if reply.is_err() {
                continue;
            }
            // Otherwise, read the reply as a message we can use
            let reply: message::RawNetworkMessage = reply.unwrap();
            // What we just received?
            match reply.payload {
                // They sent their version
                message::NetworkMessage::Version(_) => {
                    println!("Received version message:");

                    let second_message = message::RawNetworkMessage {
                        magic: constants::Network::Bitcoin.magic(),
                        payload: message::NetworkMessage::Verack,
                    };

                    let _ = stream.write_all(encode::serialize(&second_message).as_slice());
                    println!("Sent verack message");
                }
                // They acknowledged our version
                message::NetworkMessage::Verack => {
                    println!("Received verack message");
                }
                // We received the "last alert"?
                message::NetworkMessage::Alert (_) => {
                    println!("Received alert message");
                }
                // It's a address message?
                message::NetworkMessage::Addr (addr) =>
                {
                    println!("Received  addr message {:?}", addr[0].1.socket_addr());
                }
                // They're pinging with us? Send a pong!
                message::NetworkMessage::Ping (nonce) => {
                    println!("Got a ping");
                    let pong = message::RawNetworkMessage {
                        magic: constants::Network::Bitcoin.magic(),
                        payload: message::NetworkMessage::Pong(nonce),
                    };
                    let _ = stream.write_all(encode::serialize(&pong).as_slice());
                }
                message::NetworkMessage::Inv (inv_data) => {
                    println!("We got an inv {:?}", inv_data);
                    let inv = message::RawNetworkMessage {
                        magic: constants::Network::Bitcoin.magic(),
                        payload: message::NetworkMessage::Inv(inv_data),
                    };
                    let _ = stream.write_all(encode::serialize(&inv).as_slice());
                }
                message::NetworkMessage::Pong (_) => {
                    println!("Got a pong");
                }
                // Hmm, not sure what you intend to
                _ => {
                    println!("Received unknown message: {:?}", reply.payload);
                    break;
                }
            }
        }
        let _ = stream.shutdown(Shutdown::Both);
    } else {
        eprintln!("Failed to open connection");
    }
}

fn build_version_message(address: SocketAddr) -> message::NetworkMessage {
    // The address of the connection creator
    let my_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);

    // The services supported by myself
    let services = constants::ServiceFlags::GETUTXO;

    // The timestamp of now, in seconds
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time error")
        .as_secs();

    // The address of the connection receiver
    let addr_recv = address::Address::new(&address, constants::ServiceFlags::NONE);

    // The address of the connection receiver, but as protocol address
    let addr_from = address::Address::new(&my_address, constants::ServiceFlags::NONE);

    // This random nonce is mainly used for avoiding connection to self
    let nonce: u64 = 100;

    // The user agent string
    let user_agent = String::from("/rust-btc/");

    // The last block we know, unfortunately we don't have any :/
    let start_height: i32 = 0;

    // And finally, create a version message!
    message::NetworkMessage::Version(message_network::VersionMessage::new(
        services,
        timestamp as i64,
        addr_recv,
        addr_from,
        nonce,
        user_agent,
        start_height,
    ))
}

