# fidelity

`fidelity` is an open-source Rust library. It detects hostile changes to an application's runtime
environment, and it applies a response that the host selects.

> **Status:** five platforms run, each with real clean and hostile evidence. All five answer image
> identity, compare executable memory against a baseline that `start()` captured, and read tracer
> state. Windows, Linux, and Android add unaccounted code, and Android adds device compromise. The
> iOS evidence comes from the simulator, and the Windows evidence comes from a virtual machine. A
> device and a physical host have still to confirm those two. Every run used ARM64. No platform
> counts as supported until its full release evidence exists.

| Fidelity is | Fidelity is not |
|---|---|
| A local, embedded detector and response library | A remote service, attestation system, or control plane |
| Evidence and host-selected `Report`, `Deny`, `Callback`, or `Crash` actions | A security boundary against an attacker controlling the process |
| Defense in depth across five target platforms | A way to make user-mode tampering impossible |

The v1 categories are integrity, debugging, instrumentation, device compromise, virtualization, and
UI abuse. By default, every category reports a high-strength finding. An application can instead
deny protected operations, invoke a callback, or terminate the current process.

The Rust API is:

```rust
use fidelity::{Action, SignalStrength};

let handle = fidelity::new()
    .integrity(Action::Crash, SignalStrength::High)
    .debugging(Action::Deny, SignalStrength::Medium)
    .start()?;

// The structural path. A repackaged application decrypts garbage.
let host = fidelity::guarded!(&handle, "api.example.com");

// The advisory path, immediately before a protected operation.
handle.ensure_allowed()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Prefer [`guarded!()`](docs/adr/0007-value-producing-check.md). It encrypts a host constant against
the platform code identity, so there is no branch to invert: a wrong key returns a wrong value, not
an error. It expands inline for each constant and exposes no shared reader, so one hook cannot dump
every constant at once. `ensure_allowed()` is advisory, and an attacker who patches the process
inverts it by searching for one symbol. Neither is a boundary. An attacker who runs the application
once, or who hooks the identity call, recovers a guarded value.

An attacker who can modify the process can forge findings, suppress checks, bypass responses, and
read the data the application protects. Fidelity raises the cost of an attack. It cannot make a
user-mode process tamper-proof, and it is one layer beside a compiler-based hardening tool, not a
replacement for one.

## Documentation

- [Design plan](docs/plan/README.md), and the
  [locked v1 decisions](docs/plan/README.md#locked-v1-decision-index)
- [Architecture decisions](docs/adr/README.md)
- Non-normative research on [platforms](docs/research/platform-notes.md) and
  [vendors](docs/research/vendor-survey.md)

## Security

To report a defect in Fidelity itself, see [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
