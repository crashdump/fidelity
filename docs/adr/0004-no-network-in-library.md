# ADR-0004: Prohibit remote network I/O

- Status: accepted
- Date: 2026-08-07

## Decision

Fidelity contains no remote telemetry, control plane, attestation client, update checker, or other
remote network path. It neither opens application sockets nor owns certificate validation for
application traffic.

Documented, bounded loopback probes are allowed when they directly support a local detector. A
future network category may analyze TLS or certificate context supplied by the host.

## Why

The library is embedded in applications with different privacy and infrastructure requirements.
No remote communication makes deployment and audit simpler. A security library must not become an
exfiltration path or an availability dependency.

## Consequences

- Findings and diagnostics stay local unless the host explicitly exports them.
- Offline operation is complete operation.
- CI checks the dependency graph and source for accidental remote-network clients.
