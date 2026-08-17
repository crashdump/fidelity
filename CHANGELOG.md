# Changelog

`docs/plan/06-delivery.md` states that an MSRV increase is a minor version bump and appears here.
The `fidelity` crate follows SemVer. Every other crate in the workspace is an internal
implementation detail and carries no compatibility promise, so a change to one of them appears here
only when it changes what `fidelity` exposes.

This file records released versions. The work before the first release lives in the git history and
in `evidence/README.md`, which states what each platform proved and what it did not.

## 0.1.0 - 2026-08-17

This is the first published release, and it claims no supported platform.

Five platforms run. macOS, iOS, Windows, Linux, and Android answer image identity, compare
executable memory against a baseline that `start()` captures, and read tracer state. Windows,
Linux, and Android add unaccounted code. Android adds device compromise. `guarded!()` binds a
constant to the code identity on macOS, iOS, and Android.

The iOS evidence comes from the simulator, and the Windows evidence comes from a virtual machine. A
device and a physical host have still to confirm those two. Every run used ARM64.

A supported label needs the full release evidence that `docs/plan/05-verification.md` defines, and
no platform holds it yet. Treat this release as an early version. Expect the public surface to
change before 1.0.

- The `fidelity` crate is the entry point, and it alone follows SemVer.
- The `serde` feature is off by default, so a default build resolves to no external crate.
- The MSRV is Rust 1.85.
- A host that uses `guarded!()` sets `FIDELITY_BUILD_SEED` and `FIDELITY_CODE_IDENTITY` at build
  time. The build fails when either one is absent, because a default seed gives every host the
  same key.
