//! The local instrumentation endpoint capability.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::Duration;

use crate::Observation;
use crate::fact::LocalAgentState;

/// The Frida server port when the operator supplies no other address.
const FRIDA_PORT: u16 = 27_042;

/// The maximum time for the loopback connection.
const CONNECT_DEADLINE: Duration = Duration::from_millis(5);

/// The maximum time for each protocol read and write operation.
const IO_DEADLINE: Duration = Duration::from_millis(20);

/// The maximum response that the probe reads.
const MAX_RESPONSE_BYTES: usize = 1024;

/// A fixed valid WebSocket key, with its fixed RFC 6455 answer below.
const REQUEST: &[u8] = b"GET /ws HTTP/1.1\r\n\
Host: server\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Sec-WebSocket-Version: 13\r\n\r\n";

/// The RFC 6455 answer for the key in [`REQUEST`].
const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

/// Queries a local instrumentation endpoint.
pub trait LocalAgent {
    /// Whether a Frida-compatible endpoint answers on loopback.
    fn local_agent_state(&self) -> Observation<LocalAgentState> {
        probe_address(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, FRIDA_PORT)),
            CONNECT_DEADLINE,
            IO_DEADLINE,
        )
    }
}

fn probe_address(
    address: SocketAddr,
    connect_deadline: Duration,
    io_deadline: Duration,
) -> Observation<LocalAgentState> {
    if !address.ip().is_loopback() {
        return Observation::failed("the local-agent probe refused a non-loopback address");
    }

    let mut stream = match TcpStream::connect_timeout(&address, connect_deadline) {
        Ok(stream) => stream,
        Err(error) => return connection_failure(&error),
    };

    if let Err(error) = stream.set_read_timeout(Some(io_deadline)) {
        return Observation::failed(format!("the loopback read deadline failed: {error}"));
    }
    if let Err(error) = stream.set_write_timeout(Some(io_deadline)) {
        return Observation::failed(format!("the loopback write deadline failed: {error}"));
    }
    if let Err(error) = stream.write_all(REQUEST) {
        return Observation::failed(format!("the loopback protocol write failed: {error}"));
    }

    let mut response = [0_u8; MAX_RESPONSE_BYTES];
    let mut read = 0_usize;
    while read < response.len() {
        match stream.read(&mut response[read..]) {
            Ok(0) => break,
            Ok(size) => {
                read += size;
                if response[..read]
                    .windows(4)
                    .any(|window| window == b"\r\n\r\n")
                {
                    break;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                return Observation::failed("the loopback protocol read reached its deadline");
            }
            Err(error) => {
                return Observation::failed(format!("the loopback protocol read failed: {error}"));
            }
        }
    }

    if is_frida_websocket_response(&response[..read]) {
        Observation::Fact(LocalAgentState::Present {
            detail: fidelity_types::BoundedText::new(
                "a Frida-compatible WebSocket endpoint answered on loopback",
            ),
        })
    } else {
        Observation::Fact(LocalAgentState::Absent)
    }
}

fn connection_failure(error: &io::Error) -> Observation<LocalAgentState> {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => Observation::Fact(LocalAgentState::Absent),
        io::ErrorKind::TimedOut => {
            Observation::failed("the loopback connection reached its deadline")
        }
        _ => Observation::failed(format!("the loopback connection failed: {error}")),
    }
}

fn is_frida_websocket_response(response: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(response) else {
        return false;
    };
    let Some(header_end) = text.find("\r\n\r\n") else {
        return false;
    };
    let mut lines = text[..header_end].split("\r\n");
    let Some(status) = lines.next() else {
        return false;
    };
    if !status.starts_with("HTTP/1.1 101 ") {
        return false;
    }

    let mut upgrade = false;
    let mut connection = false;
    let mut accept = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("upgrade") && value.eq_ignore_ascii_case("websocket") {
            upgrade = true;
        } else if name.eq_ignore_ascii_case("connection")
            && value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        {
            connection = true;
        } else if name.eq_ignore_ascii_case("sec-websocket-accept") && value == ACCEPT {
            accept = true;
        }
    }
    upgrade && connection && accept
}

#[cfg(test)]
mod tests {
    use std::io::{self, Read, Write};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use crate::Observation;
    use crate::fact::LocalAgentState;

    use super::{connection_failure, probe_address};

    const FRIDA_RESPONSE: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";

    #[test]
    fn a_frida_websocket_exchange_reports_a_local_agent() {
        let Ok(listener) = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)) else {
            panic!("the test must bind a loopback socket")
        };
        let Ok(address) = listener.local_addr() else {
            panic!("the test must read its loopback address")
        };
        let server = thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                panic!("the test server must accept the probe")
            };
            let mut request = [0_u8; 512];
            let Ok(_) = stream.read(&mut request) else {
                panic!("the test server must read the probe")
            };
            assert!(
                stream.write_all(FRIDA_RESPONSE).is_ok(),
                "the test server must write its response"
            );
        });

        let answer = probe_address(
            address,
            Duration::from_millis(100),
            Duration::from_millis(100),
        );
        assert!(server.join().is_ok(), "the test server must stop");

        assert!(matches!(
            answer,
            Observation::Fact(LocalAgentState::Present { .. })
        ));
    }

    #[test]
    fn an_unrelated_service_reports_no_local_agent() {
        let Ok(listener) = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)) else {
            panic!("the test must bind a loopback socket")
        };
        let Ok(address) = listener.local_addr() else {
            panic!("the test must read its loopback address")
        };
        let server = thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                panic!("the test server must accept the probe")
            };
            let mut request = [0_u8; 512];
            let Ok(_) = stream.read(&mut request) else {
                panic!("the test server must read the probe")
            };
            if stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .is_err()
            {
                panic!("the test server must write its response")
            }
        });

        let answer = probe_address(
            address,
            Duration::from_millis(100),
            Duration::from_millis(100),
        );
        assert!(server.join().is_ok(), "the test server must stop");

        assert_eq!(answer, Observation::Fact(LocalAgentState::Absent));
    }

    #[test]
    fn a_refused_connection_reports_no_local_agent() {
        assert_eq!(
            connection_failure(&io::Error::from(io::ErrorKind::ConnectionRefused)),
            Observation::Fact(LocalAgentState::Absent)
        );
    }

    #[test]
    fn an_address_outside_loopback_reports_a_failure() {
        let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 27_042));
        assert!(matches!(
            probe_address(
                address,
                Duration::from_millis(100),
                Duration::from_millis(100),
            ),
            Observation::Failed { .. }
        ));
    }

    #[test]
    fn a_stalled_endpoint_reports_a_failure_at_the_deadline() {
        let Ok(listener) = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)) else {
            panic!("the test must bind a loopback socket")
        };
        let Ok(address) = listener.local_addr() else {
            panic!("the test must read its loopback address")
        };
        let (accepted_tx, accepted_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let Ok((_stream, _)) = listener.accept() else {
                panic!("the test server must accept the probe")
            };
            assert!(
                accepted_tx.send(()).is_ok(),
                "the test server must report its connection"
            );
            assert!(
                release_rx.recv().is_ok(),
                "the test must release the server"
            );
        });
        let probe = thread::spawn(move || {
            probe_address(
                address,
                Duration::from_millis(20),
                Duration::from_millis(20),
            )
        });
        if accepted_rx
            .recv_timeout(Duration::from_millis(100))
            .is_err()
        {
            panic!("the probe must connect to the test server")
        }
        let Ok(answer) = probe.join() else {
            panic!("the probe thread must stop")
        };
        assert!(
            release_tx.send(()).is_ok(),
            "the test must release the server"
        );
        assert!(server.join().is_ok(), "the test server must stop");

        assert!(matches!(answer, Observation::Failed { .. }));
    }
}
