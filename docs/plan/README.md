# Fidelity design plan

This directory is the normative product specification. Rustdoc is authoritative for the exact Rust
surface. These documents keep behavior, security semantics, and release criteria. An API shown here
that no crate implements yet is a target, not a description.

1. [Product contract](01-product.md)
2. [Security model](02-security-model.md)
3. [Runtime and API](03-runtime-and-api.md)
4. [Detectors and platforms](04-detectors-and-platforms.md)
5. [Verification](05-verification.md)
6. [Delivery](06-delivery.md)
7. [State and budgets](07-state-and-budgets.md)

The research notes on [platforms](../research/platform-notes.md) and
[vendors](../research/vendor-survey.md) are non-normative. The plan wins if they disagree with it.

## Locked v1 decision index

Settled. Reopening one needs a superseding ADR.

| Area | Locked decision | Normative detail |
|---|---|---|
| Product | Open-source embedded Rust library for detection and local prevention | [Product](01-product.md) |
| Categories | `Integrity`, `Debugging`, `Instrumentation`, `DeviceCompromise`, `Virtualization`, `UiAbuse` | [Product](01-product.md) |
| Binding | `ensure_allowed()` is advisory; `guarded!()` constants derive from the per-build key and platform code identity, no heuristic gates them, and a read needs a started runtime | [ADR-0007](../adr/0007-value-producing-check.md) |
| Actions | Exactly `Report`, `Deny`, `Callback`, `Crash`; one per category; no composition or presets | [Product](01-product.md), [ADR-0006](../adr/0006-configurable-responses.md) |
| Defaults | Every category uses `Report` with a `High` action threshold; every finding is still reported | [Security model](02-security-model.md) |
| Strength | `Low`, `Medium`, `High`; strongest-ever only; no score, aggregation, repetition escalation, or decay | [Detector model](04-detectors-and-platforms.md), [ADR-0002](../adr/0002-signal-strength-without-scoring.md) |
| Runtime | One immutable production runtime per process that runs until the process stops, with no public stop; a synchronous initial scan of the cheap detectors; the worker completes its actions before `start()` returns, then runs the rest | [Runtime](03-runtime-and-api.md), [ADR-0005](../adr/0005-library-owned-runtime.md), [ADR-0009](../adr/0009-atomic-start.md) |
| Lifecycle | Internal jittered frequent, periodic, and lifecycle work; mobile rescan on resume; no background service and no public interval | [Runtime](03-runtime-and-api.md) |
| State | Permanent category latch, bounded strongest and current detector state, no event ring, authoritative snapshot | [State and budgets](07-state-and-budgets.md) |
| Cost | Bounded memory that ignores finding frequency; `ensure_allowed()` never scans; a mobile worker never blocks suspension | [State and budgets](07-state-and-budgets.md) |
| Failure | Unsupported is metadata by default; a required category turns incomplete coverage into a typed start failure; detector failure is a `Low` health finding | [Security model](02-security-model.md), [Runtime](03-runtime-and-api.md) |
| Trust ceiling | Findings are unauthenticated and same-process, root, kernel, and equivalent attackers can bypass the library | [Security model](02-security-model.md) |
| I/O | No persistence and no remote network client; idiomatic `tracing` behind an optional feature, off by default; documented bounded loopback probes are allowed | [Runtime](03-runtime-and-api.md), [ADR-0004](../adr/0004-no-network-in-library.md) |
| Extensibility | Fixed built-in detector set; no custom detectors or runtime plugins | [ADR-0003](../adr/0003-closed-detector-set.md) |
| Platforms | Android, iOS, macOS, Windows, and glibc Linux; ARM64 and x86_64 as specified, and macOS on ARM64 alone; same public semantics | [Platforms](04-detectors-and-platforms.md) |
| Identity | Platform trust needs no host input; expected identity is host-supplied, and a call to `expected_identity()` makes it required; Fidelity ships no tool for it | [Detectors](04-detectors-and-platforms.md) |
| Bindings | Rust only in v1; no C ABI and no other FFI; the Tauri adapter exposes no WebView surface | [Delivery](06-delivery.md), [ADR-0010](../adr/0010-rust-only-tauri-adapter.md) |
| Layout | Capabilities are traits and operating systems are crates; one seam selects a platform; a feature never does | [Delivery](06-delivery.md), [ADR-0008](../adr/0008-object-safe-capability-traits.md) |
| Schema | Fidelity owns the field names and their meaning, not an encoding; `Detector` is opaque; optional `serde` feature, off by default; additive fields only | [State and budgets](07-state-and-budgets.md) |
| Deferred | Proactive hardening, obfuscation, a network category, FFI, and language bindings | [Product](01-product.md) |
| Standards | OWASP for mobile requirements and tests, D3FEND only for exact defensive mechanisms, ATT&CK only for threat behavior | [Traceability](05-verification.md) |
| Verification | Real clean and hostile backend controls; mocks and compilation do not establish implementation; the testkit stays internal, so a host proves placement against a real hostile environment | [Verification](05-verification.md) |
| License | Apache-2.0; dual licensing has not been adopted | [LICENSE](../../LICENSE) |

## Open engineering work

The [platform test record](../../tests/platform/README.md) holds the current work list. A platform
needs its full release tests before it gets the supported label. These gaps are engineering work,
not open product choices.
