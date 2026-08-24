//! Reports whether a Frida-compatible endpoint answers on loopback.
//!
//! Run the example without an endpoint for the clean control. Run a Frida
//! server on its default loopback port for the hostile control.

use std::time::Duration;
use std::{io, thread};

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};

use fidelity::{Action, Outcome, SignalStrength};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = test_endpoint(std::env::args().nth(1).as_deref())?;
    let handle = fidelity::new()
        .instrumentation(Action::Deny, SignalStrength::Medium)
        .deny_until_first_full_scan()
        .start()?;
    if !handle.wait_for_first_full_scan(Duration::from_secs(2)) {
        return Err(std::io::Error::other("the first full scan reached its deadline").into());
    }

    for state in handle.snapshot().detectors() {
        let name = state.detector().name();
        if name != "instrumentation.local_agent" {
            continue;
        }
        match state.outcome() {
            Outcome::NotRun => println!("  {name}: no scan reached it"),
            Outcome::Clean => println!("  {name}: clean"),
            Outcome::Unsupported { reason } => println!("  {name}: unsupported, {reason}"),
            Outcome::Finding(finding) => println!(
                "  {name}: {:?}, {:?}",
                finding.strength(),
                finding.evidence()
            ),
        }
    }

    match handle.ensure_allowed() {
        Ok(()) => println!("protected operation: allowed"),
        Err(denial) => println!("protected operation: denied, {denial}"),
    }
    if let Some(endpoint) = endpoint {
        endpoint
            .join()
            .map_err(|_| io::Error::other("the local endpoint thread panicked"))??;
    }
    Ok(())
}

/// Starts an in-process protocol control when the caller requests one.
fn test_endpoint(mode: Option<&str>) -> io::Result<Option<thread::JoinHandle<io::Result<()>>>> {
    let response: &'static [u8] = match mode {
        Some("frida") => {
            b"HTTP/1.1 101 Switching Protocols\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
        }
        Some("unrelated") => b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        Some(_) | None => return Ok(None),
    };
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 27_042))?;
    Ok(Some(thread::spawn(move || {
        let (mut stream, _) = listener.accept()?;
        let mut request = [0_u8; 1024];
        let _ = stream.read(&mut request)?;
        stream.write_all(response)
    })))
}
