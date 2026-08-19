# Changelog

`docs/plan/06-delivery.md` states that an MSRV increase is a minor version bump and appears here.
The `fidelity` crate follows SemVer. Every other crate in the workspace is an internal
implementation detail and carries no compatibility promise, so a change to one of them appears here
only when it changes what `fidelity` exposes.

This file records released versions. The work before the first release lives in the git history and
in `tests/platform/README.md`, which states what each platform proved and what it did not.

## Unreleased

- The `Instrumentation` category gains a second detector. `instrumentation.dispatch_targets`
  reports `Medium` when a call target of the main image points somewhere else than at start. It
  catches a hook that maps no new executable region, such as one that redirects a call to code that
  already exists, which the runtime baseline cannot see. Linux answers it through the jump-slot
  relocations of the main image, and Windows through the import address table of the main module.
  The other three platforms report `Unsupported`. `Evidence` gains a `DispatchRedirected` variant,
  which is an additive change.
- The `Virtualization` category gains its first detector. `virtualization.machine_host` reports
  `Medium` when the kernel states that a virtual machine monitor runs the system. macOS answers it,
  through `kern.hv_vmm_present`, and the other four platforms report `Unsupported`. `Evidence` gains
  a `VirtualMachineHost` variant, which is an additive change.
- A `tracing` feature reports internal events, and it is off by default. The engine reports every
  one, and each names the detector, the category, the strength, and the action. Fidelity installs
  no subscriber, so a host that turns the feature on installs its own. A default build still
  resolves to no external crate.
- An x64 image that runs under the emulation of an ARM64 Windows reports unaccounted code on every
  clean run, because the translator writes code that no file backs. The test record states the
  figure, and an ARM64 image on the same machine reports clean.

## 0.1.0 - 2026-08-17

This is the first published release, and it claims no supported platform.

Five platforms run. macOS, iOS, Windows, Linux, and Android answer image identity, compare
executable memory against a baseline that `start()` captures, and read tracer state. Windows,
Linux, and Android add unaccounted code. Android adds device compromise. `guarded!()` binds a
constant to the code identity on macOS, iOS, and Android.

The iOS results come from the simulator, and the Windows results come from a virtual machine. A
device and a physical host have still to confirm those two. Every run used ARM64.

A supported label needs the full release tests that `docs/plan/05-verification.md` defines, and
no platform holds it yet. Treat this release as an early version. Expect the public surface to
change before 1.0.

- The `fidelity` crate is the entry point, and it alone follows SemVer.
- The `serde` feature is off by default, so a default build resolves to no external crate.
- The MSRV is Rust 1.85.
- A host that uses `guarded!()` sets `FIDELITY_BUILD_SEED` and `FIDELITY_CODE_IDENTITY` at build
  time. The build fails when either one is absent, because a default seed gives every host the
  same key.
