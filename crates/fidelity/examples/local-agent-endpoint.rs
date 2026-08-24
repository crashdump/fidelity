//! Serves one deterministic local-agent protocol control.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};

const FRIDA_RESPONSE: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";

const UNRELATED_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let unrelated = std::env::args()
        .nth(1)
        .is_some_and(|value| value == "unrelated");
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 27_042))?;
    println!("the local endpoint is ready");
    let (mut stream, _) = listener.accept()?;
    let mut request = [0_u8; 1024];
    let _ = stream.read(&mut request)?;
    let response = if unrelated {
        UNRELATED_RESPONSE
    } else {
        FRIDA_RESPONSE
    };
    stream.write_all(response)?;
    Ok(())
}
