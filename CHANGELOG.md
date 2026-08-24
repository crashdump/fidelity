# Changelog

`docs/plan/06-delivery.md` states that an MSRV increase is a minor version bump and appears here.
The `fidelity` crate and `tauri-plugin-fidelity` follow SemVer. Every other crate is an internal
implementation detail and carries no compatibility promise. A change to one appears here only when
it changes one of those two public surfaces.

This file records released versions and the current release candidate. The work before the first
release lives in the git history and in `tests/platform/README.md`, which states what each platform
proved and what it did not.

## 0.4.0 - 2026-08-24

This release is the v1 beta. It adds three detectors, resolves the last planned platform cell, and
extends guarded values to Windows and byte strings. It also closes runtime and host-integration
gaps before the v1 release proof.

### Detector coverage

- `instrumentation.local_agent` sends a bounded protocol query to loopback. A port alone creates no
  finding. The peer must answer a Frida-compatible WebSocket exchange.
- The loopback probe uses no DNS or non-loopback address. It caps its read and its deadline. It runs
  in a full scan rather than the synchronous cheap scan.
- Frida 17.17.0 supplies the real hostile control on macOS. An exact protocol control and an
  unrelated service run on all five platforms.
- `instrumentation.image_catalog` compares executable file mappings with the loader catalog on
  Linux, Android, and Windows. It reports `Medium` when a file-backed image bypasses the loader.
- The image-catalog clean controls cover normal late loads and runtime code. The hostile control
  maps a valid library image without loader registration.
- `device_compromise.verified_boot` reads the Android verified-boot color and the vbmeta device
  state. It uses `ro.boot.flash.locked` only as a compatibility fallback.
- An unlocked or unverified boot reports `Medium`. A missing or conflicting answer reports a `Low`
  health finding rather than a clean device.
- A locked physical device supplies the verified-boot clean control. The hostile property states
  have deterministic controls. A real unlocked-device control remains open.
- Each new detector gets a narrow capability. The release adds no detector plug-in system and no
  second platform pattern.

### Guarded values

- Windows gains code-identity binding for `guarded!()`. The binding uses the SHA-256 digest of the
  Authenticode signer certificate that the Windows probe already reports.
- A trusted signer, another signer, and an unsigned image supply the Windows controls. The wrong
  signer returns a wrong guarded value with no error path.
- `guarded_bytes!()` protects a byte-string literal and returns a bounded value that wipes on drop.
  It permits data that the printable string alphabet cannot hold.
- The byte form keeps one inline reader per call site. It shares the existing key schedule and adds
  no common decryption function.
- The artifact tests reject plaintext and recover each value with the correct public inputs. They
  recover no value with another identity, and two seeds produce two different artifacts.

### Runtime and failure contracts

- The cheap and full scan sets become different for the first time. The loopback detector runs in
  the full set, and the other bounded detectors remain in both sets.
- `require_complete_coverage()` runs each required detector before success. This includes a bounded
  full-only detector when its category is required.
- `deny_until_first_full_scan()`, `first_full_scan_complete()`, and the bounded wait gain controls
  against the real full-only detector.
- After a resume, the worker completes `scan_all()` before it applies a pending host callback or a
  pending stop action.
- The resume control suspends the worker during its wait and during an active scan. Both paths must
  put a new full scan before host code.
- A capability error remains `Observation::Failed` through start and every worker path. It becomes
  a `Low` health finding and never a clean or unsupported result.
- A detector panic stays inside that detector. The worker continues the scan and later cycles.
- The loopback deadline, a callback panic, a failed platform read, and a worker setup failure each
  get a deterministic control.
- The implementation keeps two scan sets and one worker loop. It adds no general task scheduler.

### Platform completion

- `MachineHost` distinguishes a virtual machine from a simulator or an emulator.
  `SimulatedEnvironment` carries the new public evidence without a false monitor claim.
- iOS gains `emulation`. A physical device and a simulator supply the `machine_host` controls.
- The iOS `device` cell becomes `no`. The iOS 26.5 SDK exposes no public compromise state, and a
  provisioned iOS 26.6.1 application receives `EPERM` from `kern.securelevel`.
- The release adds no jailbreak path list. A missing public state stays visible as `Unsupported`.
- The clean iOS device also proves a signed team identity and the bounded local-agent exchange.
- A physical Android device proves its build state, hardware host, signed archive, guarded values,
  and system-driven resume.
- The Android harness runs on ARM64 hardware. The cross-check builds ARM64 and x86-64 Android
  targets. The minimum release gets a build check.
- The project guests supply the hostile Linux and Windows `machine_host` controls. The clean
  physical-host controls remain open.
- Linux and Windows run the detector controls on ARM64. Windows also runs selected controls through
  x64 emulation and signs the identity subjects in the guest.
- macOS 26 on ARM64 gets all runtime controls on a physical host and the project guest.
- The platform record must show each required control on all five platforms. A platform gets the
  supported label only after its record is complete.

### Tauri and host integration

- The Tauri adapter gains fallible handle access with a typed error. A missing plug-in no longer
  needs a panic as the only answer.
- The Rust extension supplies direct methods for the denial check and a `UiAbuse` report. It still
  exposes no WebView command or frontend event.
- A Tauri mock application proves setup, state access, a denial, a host report, and an initial
  full-scan wait.
- The package gate checks both fallible access paths and the compatibility panic path on macOS.

### Compatibility and release proof

- The project accepts the expanded Rust surface and the Serde shape as the v1 compatibility
  baseline. The surface and schema tests hold that baseline.
- The existing process-map fuzz target reaches the new image-catalog classification. The release
  run covers all 14 hostile-input targets.
- The sanitizers cover the socket boundary and all probe code. Miri covers the new portable state
  and detector paths. The package gate covers each facade feature and both Tauri access paths.
- The release publishes all versioned workspace crates and `tauri-plugin-fidelity` to crates.io.
  A clean consumer builds `fidelity` on Rust 1.85 and the adapter on Rust 1.88.
- The dependency graphs must contain no RustSec vulnerability, unaccepted source, remote runtime
  client, or accidental WebView surface.
- `main`, the `v0.4.0` tag, the manifest version, the test record, and the public release must
  identify one commit.

This release adds no new category, remote service, remote attestation, proactive OS enforcement,
language binding, or obfuscation.

## 0.3.0 - 2026-08-21

- Hosts can require complete platform detector coverage for a category. An unsupported, absent, or
  unhealthy detector then returns `StartError::RequiredCoverageUnavailable`. A later detector in
  that category becomes required automatically.
- `start()` now returns after every initial action completes. An initial callback receives the
  `Handle` and the `Finding`, and it completes before success. An initial `Crash` stops the process
  before success. `StartError::WorkerStoppedDuringStart` reports an early worker stop.
- Every platform gains controls for executable code that becomes writable and for the 1024-region
  baseline limit. All five controls pass on ARM64. The Android control ran on an Android 16 and API
  36 emulator.
- An independent fuzz workspace attacks 14 hostile-input families. It adds Mach-O image commands,
  bounded text, and identity inputs to the 11 reader families from the first scope.
- Linux and Android use safe ELF readers for dispatch tables. Apple uses safe Mach-O readers for
  dispatch and code-signature commands. Windows uses the safe PE readers.
- Apple checks each raw parser range with the Mach VM map. Windows copies readable image pages into
  a bounded parser buffer, so a Rust slice never crosses an inaccessible gap.
- Runtime state, public snapshots, baselines, dispatch tables, and pending actions use exact bounded
  storage. The pending queue owns a fixed 16-entry array.
- Region and dispatch comparisons use one forward pass. Fixed-seed tests compare them against simple
  reference rules across 1,024 generated cases.
- The process deny word is the latch linearization point. A snapshot cannot show a latch before
  `ensure_allowed()` denies.
- A failed or unwound start rolls back the slot, latch, coverage state, and startup policy. A
  64-thread control proves that one start owns the slot.
- `Handle::wait_for_first_full_scan()` supplies a bounded coverage wait. A 64-waiter control proves
  that one completion releases all waiters without loss.
- A panic in platform worker setup becomes a typed setup failure instead of escaping from
  `start()`.
- Android now selects the application archive from the loaded image that holds Fidelity. A private
  process and a global process use the same image rule, independent of the process name.
- The optional Serde surface has an exact data-model fixture for every public type and each
  `Evidence` variant. Public runtime read types have compile-time `Send` and `Sync` checks.
- The package gate checks all facade feature combinations on Rust 1.85. It checks the Tauri adapter
  on Rust 1.88. It compares two independent archive sets byte for byte before it builds a consumer.
- The Tauri adapter now needs Rust 1.88. Patched `plist`, `quick-xml`, and `time` releases require
  that version. The locked adapter graph contains no RustSec vulnerability.
- `tauri-plugin-fidelity` supplies a Rust-only Tauri 2 lifecycle adapter. It starts Fidelity in the
  plugin setup hook, stores the `Handle` in Rust state, and exposes no WebView interface. A Tauri
  mock-runtime test executes that setup path.

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
