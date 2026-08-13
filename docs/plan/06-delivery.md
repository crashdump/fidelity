# Delivery

## Two axes

A capability is one question that detectors ask the operating system. An operating system is one
place where every answer needs different code. The two grow independently, so each takes its own
axis:

- **Capabilities are traits.** `fidelity-core/src/capability/` holds one trait for each, and every
  method defaults to `Unsupported`. `Environment` inherits them all, so the engine holds one value.
- **Operating systems are crates**, under `crates/probe/`. One crate holds all of that system's
  `unsafe` code and all of its platform dependencies.

Every probe crate takes the same internal shape. To find which systems answer a question, list that
capability's file name across the probe crates. A capability that a system does not answer gets an
empty `impl`, which states the gap without a method body to read.

Cargo selects a probe with `[target.'cfg(...)'.dependencies]`, never with a feature. A feature is
additive and global, so `--all-features` would compile Windows code on macOS, and a feature that a
host forgets would silently drop protection. Features stay for optional capabilities such as
`serde`.

`fidelity-detect` mirrors the same idea on the category axis: one module for each `Category`, and
one file for each detector inside it.

## Workspace layout

The tree below is the target shape. A crate arrives when a real caller needs it, and not before.

```text
crates/
  fidelity/                  supported public Rust facade, the only SemVer surface
    build.rs                   states whether this build binds to a code identity
    src/backend.rs             the one seam that maps a target to its probe
  fidelity-types/            stable public data model, and no logic
  fidelity-core/             capability traits and normalized fact types
    src/capability/            one trait for each question
    src/fact/                  one module for each capability, with the same name
  fidelity-detect/           fixed built-in detector composition
    src/<category>/            one module for each category
  fidelity-engine/           state, policy, worker
  fidelity-cipher/           key derivation and the guarded-constant stream
  fidelity-macros/           proc-macro crate that expands `guarded!()`
  fidelity-formats/          pure readers of operating-system data, and no platform code
  fidelity-testkit/          deterministic multi-runtime test support
  probe/
    measure.rs                 the loop that every `cost` example includes, and no crate owns
    fidelity-probe-apple/      macOS and iOS
      build.rs                   framework links, and the Swift package
      swift/                     native code, where no C interface exists
      src/sys/                   all `unsafe`, one file for each framework
      src/common/                capability code that both Apple systems run
      src/macos/                 the macOS environment and its capabilities
      src/ios/                   the iOS environment and its capabilities
    fidelity-probe-android/    Android
      android/                   native code, as a library project
        harness/                   the cdylib that its instrumented tests load
    fidelity-probe-linux/      glibc Linux
    fidelity-probe-windows/    Windows
bindings/
  tauri-plugin-fidelity/     Rust-backend-only Tauri lifecycle adapter
evidence/                    generated release records, which nobody compresses
```

`fidelity` is the supported entry point. Probe crates expose facts, not policy. Detector composition
is fixed at compile time. Fidelity loads no detector at run time, and it exposes no third-party
detector trait.

Cargo makes the separation in [ADR-0001](../adr/0001-probe-detector-separation.md) structural: a
probe crate cannot import a detector, and every crate except the probe crates sets
`#![forbid(unsafe_code)]`. The tests in [verification](05-verification.md) check both.

## Three layers

Fidelity separates what it reads from what it interprets. Two layers sit in the probe crate, and
the middle one does not:

| Layer | Where | Holds | Runs its tests |
|---|---|---|---|
| boundary | `sys/` in the probe crate | all `unsafe`, the foreign interface, and safe wrappers | on that system only |
| reader | `fidelity-formats` | pure readers of the bytes and text that `sys/` returns | on any machine, from a fixture |
| capability | one module in the probe crate | the two above, combined into one fact | on that system only |

The split is what makes the testability claim in ADR-0001 true. A root detector reads
`/proc/self/maps` through `sys/`, and a pure reader turns that text into mappings. The reader takes
a captured file, so its tests run on a developer machine that is not Linux.

The reader must live outside the probe crate for that to hold. A probe crate carries a target
condition, because it is one operating system, so a reader inside it could only be tested on that
operating system. `fidelity-formats` therefore sits off the platform axis: no target condition, no
`unsafe` code, and no dependency on another crate. Its `procfs` module already serves Linux, and
Android reads the same text.

## Native code

Native code lives inside the probe crate that owns it. Only two platforms need any:

| Platform | Native | Why |
|---|---|---|
| Android | Kotlin, as a library project | The package, accessibility, overlay, and lifecycle APIs are Java only. One call from Kotlin replaces a long sequence of JNI calls. |
| Apple | Swift, as a package | A few interface and lifecycle APIs have no C form. macOS needs almost none, because the Security framework, Mach, dyld, and sysctl are all C. |
| Windows | none | Win32 is C, so `sys/` calls it. |
| Linux | none | The system call interface is C, so `sys/` calls it. |

Native code adds a build step and a second language to review, so a probe adds it only when the
platform offers no C interface. Mobile support therefore works for any Rust host, and not only for
Tauri.

## Platform code lives in a probe

Exactly one file outside `crates/probe/` selects a platform: `fidelity/src/backend.rs`. It maps the
target to its probe and does nothing else. Every other crate compiles the same source on every
target.

Two rules keep that true:

- No crate outside `crates/probe/` carries a `#[cfg]` on `target_os` or `target_arch`, and
  `backend.rs` is the single exception.
- The `cfg!` macro stays allowed everywhere, because it is a value and not a gate. Every arm
  compiles on every target, which is how `Platform::target()` stays portable.

A platform need that looks like it belongs to the engine is a capability that nobody declared yet.
The worker is the example: Android attaches its thread to the JVM, Apple gives the thread a quality
of service, and a mobile system reports that it resumed the application. All three are platform
code, so the `lifecycle` capability carries them and the engine stays portable.

## Capability coverage

The marker states what the code does today, and a test enforces every cell. See
[verification](05-verification.md).

- `yes`: the probe holds platform code, in a module that carries the name of the row.
- `plan`: the platform can answer, and no code exists yet.
- `no`: the platform cannot answer, so the probe writes an empty `impl`, which states the gap.

| Capability | Category | macOS | iOS | Windows | Linux | Android |
|---|---|---|---|---|---|---|
| `identity` | `Integrity` | yes | yes | plan | yes | yes |
| `baseline` | `Integrity` | yes | yes | yes | yes | yes |
| `tracer` | `Debugging` | yes | yes | yes | yes | yes |
| `injection` | `Instrumentation` | no | no | yes | yes | yes |
| `device` | `DeviceCompromise` | no | plan | no | no | yes |
| `emulation` | `Virtualization` | plan | plan | plan | plan | plan |
| `interface` | `UiAbuse` | no | plan | no | no | plan |
| `lifecycle` | none | yes | yes | no | no | yes |

A `plan` cell and a `no` cell both report `Unsupported`, which reaches the host's snapshot, so a
host always sees what its platform lacks. A `plan` cell becomes `yes` in the same change that adds
the code, because the test fails while the two disagree.

Every capability except `lifecycle` needs a detector, and the same test checks that. `lifecycle`
carries the category `none`, because it answers no question and reports no finding.

## Implementation sequence

1. Stabilize the types, configuration, lifecycle, state retention, and testkit.
2. Implement platform code identity vertically through one real backend, and land `guarded!()` on
   it. Identity is one narrow mechanism, and it is the input that the structural path needs, so it
   comes before the heuristic detectors. Done on macOS.
3. Prove the two axes with more capabilities and more operating systems. Done: four capabilities
   run across macOS, iOS, Linux, and Android. Two share one pure reader, and two more share one
   `common/` body inside the Apple crate.
4. Add a platform mechanism only with clean and hostile evidence, and explicit capability semantics.
5. Complete all five target backends and the release matrix.
6. Stabilize the finding and snapshot schema, and publish the first supported Rust release.

Post-v1 candidates are proactive hardening, host-supplied network analysis, and language bindings.
They must not shape the v1 public API early.

## Engineering constraints

- Rust with `std` is required. Fidelity does not support pure `no_std`.
- `Cargo.toml` pins the MSRV to one concrete Rust version, at or below the current stable release
  minus two. A new Rust release never raises it. CI builds the pinned MSRV and current stable. An
  MSRV increase is a minor version bump and appears in the changelog. `evidence/run.sh` builds the
  pinned version on every target, because a pin that nothing builds is a claim rather than a fact.
- The public surface of the `fidelity` crate follows SemVer. Every other crate is an internal
  implementation detail and carries no compatibility promise.
- `Category`, `Evidence`, `Platform`, `IdentityError`, `StartError`, and `DenialReason` are
  `#[non_exhaustive]`, because all six grow after v1. `Action`, `SignalStrength`, and `Outcome` stay
  exhaustive, so the common host match needs no wildcard arm.
- Platform `unsafe` stays in the `sys/` module of a probe crate, with documented invariants and safe
  wrappers. No caller outside `sys/` holds a raw pointer.
- Every capability trait stays object safe. See
  [ADR-0008](../adr/0008-object-safe-capability-traits.md).
- `fidelity-probe-android` finds the virtual machine itself, with `JNI_GetCreatedJavaVMs`, so the
  host passes no handle and the public API gains no Android-only field. Measured on Android 37: the
  call reports the same machine that JNI handed the host, and `libnativehelper.so`, which exports
  it, is on the public library list that an application may link. The probe still defines no
  `JNI_OnLoad`, because one shared library holds one such function and the host owns it. The worker
  attaches once as a daemon thread and never detaches, because the runtime never stops, and a plain
  attachment would keep the machine alive and stop the application from ending.
- Dependencies are minimal, pinned, audited, and selected per target where possible. A default build
  of the workspace resolves to no external crate, and a security library keeps that property while
  it can. The optional `serde` feature is the one exception, and it is off by default, so a host
  that never asks for it never gets it.
- The engine does not require Tokio. The Tauri adapter may bridge findings to an application
  runtime without exposing them to the webview.
- v1 exposes no C ABI and no other FFI entry point. Language bindings come after the Rust contract
  is stable, and they carry their own unwind and panic-strategy design.
- CI verifies forbidden remote-network dependencies and public-surface drift.
- `fidelity-macros` expands `guarded!()` in the host's own compilation, because that is where the
  call sites are. It reads the build seed and the code identity from the environment, and it fails
  the build when either is absent. Its build script must declare both with
  `cargo:rerun-if-env-changed`. Without those lines Cargo does not re-expand, and a rotated seed
  silently keeps the old key. CI must prove that two seeds give two binaries.
  See [ADR-0007](../adr/0007-value-producing-check.md).
- The `fidelity` build script reads the code identity as well, so `start()` knows whether this build
  binds to one and can refuse an image that supplies none. Both scripts run in one Cargo invocation
  and read one environment, so the two never disagree.
- The host's release profile should set `lto`, `codegen-units = 1`, and `strip`. Fidelity's
  functions then inline into their callers and lose their names, so an attacker cannot find a check
  by reading the symbol table.

## Build and check commands

CI runs each of these, and a change is complete only when all of them pass:

| Command | Covers |
|---|---|
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | lints |
| `cargo test --workspace --all-features` | every test layer that the host machine can run, and the optional `serde` surface |
| `cargo fmt --check` | format |
| `cargo doc --workspace --no-deps` | rustdoc, with no warning |
| `cargo check --workspace --target <each of the five>` | every probe crate, from one machine |
| `evidence/controls/run-sanitizers.sh` | the address and thread sanitizers over the workspace |

The last row replaces what a per-platform feature would give. A probe crate compiles only for its
own target, so a cross-check is the only way to know that the Android code still builds after a
change to a capability trait. It needs no device, no emulator, and no NDK.

`evidence/run.sh` runs every row above, and CI runs that one script and states no command of its
own. A second list in a workflow file would drift from this one, and the copy that drifts is the
copy that decides whether a change lands. CI runs the script on a macOS runner and on a Linux
runner, because each one reaches controls that the other cannot. A runner reaches no device and no
simulator, so the harness records a skipped row for each with the reason, and a green run never
claims more than it tested.

The project may declare crate boundaries early, but implementation proceeds vertically. A platform
package must not contain a fake detector success or a shallow stub that makes the five-platform
matrix look populated. Label every compilation-only placeholder explicitly, and keep it minimal.
Only the [verification criteria](05-verification.md) define platform support.
