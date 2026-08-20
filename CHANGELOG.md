# Changelog

`docs/plan/06-delivery.md` states that an MSRV increase is a minor version bump and appears here.
The `fidelity` crate follows SemVer. Every other crate in the workspace is an internal
implementation detail and carries no compatibility promise, so a change to one of them appears here
only when it changes what `fidelity` exposes.

This file records released versions. The work before the first release lives in the git history and
in `tests/platform/README.md`, which states what each platform proved and what it did not.

## 0.2.0 - 2026-08-20

- The `Instrumentation` category gains a second detector. `instrumentation.dispatch_targets`
  reports `Medium` when a call target of the main image points somewhere else than at start. It
  catches a hook that maps no new executable region, such as one that redirects a call to code that
  already exists, which the runtime baseline cannot see. Every platform answers it. Linux answers it
  through the jump-slot relocations of the main image, and Windows through the import address table
  of the main module. macOS and iOS answer it through the non-lazy symbol pointers of the main
  image, and only when that image carries `LC_DYLD_CHAINED_FIXUPS`, which a deployment target of
  macOS 13 or iOS 15 produces and the v1 floor exceeds. An image below that threshold binds an
  import on its first call, so the probe reports `Unsupported` rather than a false finding. Android
  reads the jump-slot relocations of the library that holds Fidelity, and not of the main image: an
  application forks from zygote, so its main image is `/system/bin/app_process64`, which every
  application shares and which no call of the host reaches. `Evidence` gains a `DispatchRedirected`
  variant, which is an additive change.
- The `Virtualization` category gains its first detector. `virtualization.machine_host` reports
  `Medium` when the system states that a virtual machine monitor runs below it. Four platforms
  answer. macOS reads `kern.hv_vmm_present`, Linux reads the firmware tables and the virtio
  devices, Windows reads the firmware tables, and Android reads the bootloader properties. iOS
  reports `Unsupported`, because a simulator process reads the kernel of the Mac below it and this
  project has read no device. `Evidence` gains a `VirtualMachineHost` variant, which is an additive
  change.
- The `UiAbuse` category gains its first detector. `ui_abuse.host_report` reports `Medium` when the
  host reports that another application drew over its window, or that a recorder captured one. It
  reads no operating system, because two measurements showed that no operating system answers this
  question to a library. `Handle::report_ui_abuse` and `UiObservation` are the surface, and both are
  additive.
- A `tracing` feature reports internal events, and it is off by default. The engine reports every
  one, and each names the detector, the category, the strength, and the action. Fidelity installs
  no subscriber, so a host that turns the feature on installs its own. A default build still
  resolves to no external crate.
- A build on Rust 1.85 works again. `Cargo.toml` names 1.85 as the minimum version and
  `docs/plan/06-delivery.md` makes that normative, and two `let` chains that need 1.88 had landed
  after the 0.1.0 release. A host that took the named minimum could not build the workspace at all.
  Both are written the older way now, and the platform harness builds the pinned version on every
  run, so the claim and the check cannot separate again.
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
