# The platform test record

This directory holds the record that [verification](../../docs/plan/05-verification.md) requires, and
the controls that produce it. No size rule applies here, and nobody compresses a test record.

A cell reads `yes` only after a real run on a real system. A mock, a stub, and a successful
compilation do not count. A gap in this record is what blocks a platform from the supported
label, so the [gaps](#gaps) below are the work list.

`05-verification.md` asks for a generated record, and `run.sh` produces it. The harness runs every
control that the machine can reach and writes `record.tsv`, with one row for each control: the
system, the result, and a detail. A control that this machine cannot reach gets a `skipped` row that
says why. A control that needs a person gets a `manual` row that names the section below where the
result lives. The skipped rows carry the weight, because no machine reaches every system that
Fidelity supports, and a record of what passed alone would read as complete coverage.

CI runs this harness and states no command of its own, so a green run there means exactly what a
green run here means, minus the rows that a runner has to skip. `docs/plan/06-delivery.md` holds
the command list, and one copy of it is the point.

This file holds the judgment, and `record.tsv` holds what ran. Two rules in
`crates/fidelity/tests/test_record.rs` bind them: a capability cannot report `yes` in the
[coverage matrix](../../docs/plan/06-delivery.md#capability-coverage) while this record stays silent
about it, and the harness must name every control that exists.

## Detector coverage

Every finding below reports at the strength that
[detectors and platforms](../../docs/plan/04-detectors-and-platforms.md) states. Every run used ARM64.
The capability and system names match the coverage matrix exactly, because the test compares them.

| Capability | Detector | System | Measured on | Clean control | Hostile control, and the result |
|---|---|---|---|---|---|
| `identity` | `integrity.platform_trust` | macOS | macOS 26, 2026-08-18 | a distributed image, which a person measured, because this tier needs a certificate that the machine anchors | `identity-adhoc-macos`: a local build carries the ad-hoc signature that the linker writes, which fails `anchor apple generic`, and the tier reports `Medium` and `SecCodeCheckValidity returned -67050`. A repackaged image reports the same. |
| `identity` | `integrity.expected_identity` | macOS | macOS 26, 2026-08-18 | `identity-clean-macos`: the running image, pinned to its own cdhash, stays clean. A code requirement may name a cdhash rather than a signer, so this arm needs no certificate. A distributed image and a second certificate of the same team both stay clean, and a person measured those two. | `identity-repackaged-macos`: a copy that another party re-signs under another identifier keeps every byte of the code, gets another cdhash, and reports `High`. `identity-pinned-other-macos`: the same image against a team it does not carry reports `High`. Both deny the operation. |
| `identity` | `integrity.platform_trust` | iOS | iOS 26, simulator | the tier reports `Unsupported`, because the iOS SDK ships no `SecCode.h`, checked 2026-08-10 | none. An `Unsupported` tier creates no finding, so it has no hostile control. |
| `identity` | `integrity.expected_identity` | iOS | iOS 26, simulator, 2026-08-18 | `identity-clean-ios`: an ad-hoc build names no team, and an absent host value reports `Unsupported` and allows the operation | `identity-pinned-team-ios`: a pinned team, against that same image, reports `High` and denies the operation |
| `identity` | `integrity.platform_trust` | Android | Android 37, emulator | the tier reports `Unsupported`, because Android accepts any self-signed certificate and anchors none | none. An `Unsupported` tier creates no finding, so it has no hostile control. |
| `identity` | `integrity.expected_identity` | Android | Android 37, emulator | an instrumented test reads the certificate of its own archive, and it equals what `PackageManager` reports for the same package | a pinned digest against another certificate, which reports, `High` |
| `identity` | `integrity.platform_trust` | Linux | Debian 13, kernel 6.12, in the QEMU guest, 2026-08-13 | both arms ran. On an ordinary filesystem the ioctl answers that the image carries no fs-verity, and the tier reports `Unsupported`. On an ext4 filesystem made with `-O verity`, and with verity enabled on the image, the tier reports `Accepted`. | none. This tier accepts or states a gap, and it creates no finding either way. |
| `identity` | `integrity.expected_identity` | Linux | Debian 13, kernel 6.12, in the QEMU guest, 2026-08-13 | the running image, pinned to the digest of its own content, stays clean | the same image with one byte appended, against the digest of the original, which reports, `High`. An appended byte leaves an ELF image runnable and changes its content, so the control repackages a real artifact. |
| `identity` | `integrity.platform_trust` | Windows | Windows 11 Pro, build 10.0.26200, ARM64, in the QEMU guest, 2026-08-16 | a copy that `controls/sign-windows.ps1` signs with a certificate that the machine anchors. The tier reports clean. | the same copy, signed with a certificate that nothing anchors, which reports `Medium`, `the Authenticode signature of the running image did not validate`. An unsigned build reports `Medium` and states that it carries no signature, so all three answers of the tier have a control. |
| `identity` | `integrity.expected_identity` | Windows | Windows 11 Pro, build 10.0.26200, ARM64, in the QEMU guest, 2026-08-16 | the signed copy, pinned to the SHA-256 of the certificate that signed it. The tier reports clean, and the operation is allowed. | the same copy, pinned to another certificate, which reports `High`, `the running image carries another signing certificate`, and the operation denied. The copy that nothing anchors reports the same, and both tiers then report together. |
| `baseline` | `integrity.runtime_baseline` | macOS | macOS 26 | two JavaScript hot loops, which add no region, and 40 s with no finding | an agent maps 64 KiB after start, caught after 5.6 s to 7.1 s, `Medium` |
| `baseline` | `integrity.runtime_baseline` | iOS | iOS 26, simulator, 2026-08-18 | `baseline-clean-ios`: 40 s with no finding | `baseline-hostile-ios`: `delayed.c` maps 64 KiB after start, caught after 5.7 s, `Medium`. `simctl spawn` carries a variable to the child under the `SIMCTL_CHILD_` prefix only, so a plain `DYLD_INSERT_LIBRARIES` inserts nothing and the run then reads as clean. |
| `baseline` | `integrity.runtime_baseline` | Linux | Debian, glibc | 40 s with no finding | an `LD_PRELOAD` agent maps 64 KiB after start, caught after 6.1 s to 6.8 s, `Medium` |
| `baseline` | `integrity.runtime_baseline` | Android | Android 37, emulator, 2026-08-18 | `baseline-clean-android`: 40 s with no finding. A system application maps 410 regions, which is what sets the snapshot limit. | `baseline-hostile-android`: `delayed.so`, through `LD_PRELOAD`, maps 64 KiB after start, caught after 6.8 s, `Medium`, `executable memory that start did not map: 65536 bytes, region count 1` |
| `baseline` | `integrity.runtime_baseline` | Windows | Windows 11 Pro, build 10.0.26200, ARM64, in the QEMU guest, 2026-08-15 | 40 s with no addition, and the detector holds that answer for the whole run | `inject-windows.c` maps 64 KiB into the process after `start()` read the baseline, caught after 5.3 s, `Medium`, `executable memory that start did not map: 65536 bytes, region count 1` |
| `tracer` | `debugging.tracer_present` | macOS | macOS 26 | a run with no debugger | `lldb`, at start and attached later, both report, `Medium`, and the later one is caught after 5.4 s to 5.8 s |
| `tracer` | `debugging.tracer_present` | iOS | iOS 26, simulator, 2026-08-18 | `tracer-clean-ios`: a run with no debugger | `lldb` in both of its forms. `tracer-at-start-ios` runs the whole program under it, which the initial scan finds, and `tracer-attaches-ios` attaches to a process that already runs, which the worker catches after 5.5 s. Both report `Medium` and deny the operation. |
| `tracer` | `debugging.tracer_present` | Linux | Debian, glibc | a run with no debugger | `gdb`, and `attach.c` in both of its forms, all report, `Medium`, and the later one is caught after 5.3 s to 5.8 s |
| `tracer` | `debugging.tracer_present` | Android | Android 37, emulator, 2026-08-18 | `tracer-clean-android`: a run with no tracer | `attach.c` in both of its forms, built with the NDK. `tracer-at-start-android` traces the subject from the start, which the initial scan finds, and `tracer-attaches-android` attaches to a process that already runs, which the worker catches after 6.3 s. Both report `Medium`, `the kernel reports a TracerPid on this process`, and both deny the operation. |
| `tracer` | `debugging.tracer_present` | Windows | Windows 11 Pro, build 10.0.26200, ARM64, in the QEMU guest, 2026-08-15 | a run with no debugger reports clean | `attach-windows.c` in both of its forms. It traces the subject from the start, and it attaches to a subject that already runs, which the detector catches after 6.1 s. Both report `Medium`, `the kernel reports a debugger on this process`, and both deny the operation |
| `injection` | `instrumentation.unaccounted_code` | Linux | Debian, glibc | a plain process holds no anonymous executable region | an `LD_PRELOAD` agent maps 4 KiB, reports, `Medium` |
| `injection` | `instrumentation.unaccounted_code` | Android | Android 37, emulator, 2026-08-18 | `inject-clean-android`: a plain run accounts for every executable region it holds. A real runtime names its code caches `[anon_shmem:dalvik-jit-code-cache]`, so they stay distinct from anonymous memory. | `inject-hostile-android`: `agent.so`, through `LD_PRELOAD`, maps 16 KiB with no file behind it, reports `Medium`, `unaccounted executable memory: 16384 bytes, region count 1` |
| `injection` | `instrumentation.unaccounted_code` | Windows | Windows 11 Pro, build 10.0.26200, ARM64, in the QEMU guest, 2026-08-15 | a plain run accounts for every executable region that it holds | `inject-windows.c` maps 64 KiB with no file behind it, before the subject runs its first instruction, reported `Medium`, `unaccounted executable memory: 65536 bytes, region count 1`, and the operation denied |
| `dispatch` | `instrumentation.dispatch_targets` | Linux | Debian 13, kernel 6.12, in the QEMU guest, 2026-08-19 | `dispatch-clean-linux`: the `redirect` example runs 40 s with no finding. The main image binds its dispatch table fully, so every entry holds its start value and none moves. | `dispatch-hostile-linux`: `hook.c` points the `memcpy` entry of the main image at `memmove`, which answers every call, so the subject keeps running. The runtime baseline stays clean, and this detector reports after 5.6 s, `Medium`, `dispatch targets of the main image that start did not hold: 1`. |
| `dispatch` | `instrumentation.dispatch_targets` | Windows | Windows 11 Pro, build 10.0.26200, ARM64, in the QEMU guest, 2026-08-19 | `dispatch-clean-windows`: the `redirect` example runs 40 s with no finding. Measured on the same guest: the main module holds 71 import entries, none outside a loaded image and none that moved over three seconds, because Windows binds the static import table at load. | `dispatch-hostile-windows`: `iat-hook-windows.c` redirects the `SetUnhandledExceptionFilter` import of the running subject to an address that another import already holds, from outside with `WriteProcessMemory`. The import sits in a data section, so the runtime baseline stays clean, and this detector reports after 7.0 s, `Medium`, `dispatch targets of the main image that start did not hold: 1`. |
| `emulation` | `virtualization.machine_host` | macOS | macOS 26.5 bare metal and macOS 26.6.2 in the guest, 2026-08-18 | `machine-hardware-macos`: this development machine, a MacBookPro18,4, reports `kern.hv_vmm_present=0`, so the detector reports clean and the operation is allowed | `machine-guest-macos`: the same binary inside the Virtualization.framework guest that `tests/platform/vm/macos/` builds reports `kern.hv_vmm_present=1`, and the detector reports `Medium`, `the kernel reports kern.hv_vmm_present=1, so a virtual machine monitor runs this system`, and the operation is denied |
| `emulation` | `virtualization.machine_host` | Linux | Debian 13, kernel 6.12, in the QEMU guest, 2026-08-19 | none. This project owns no bare-metal Linux, and every Linux control runs in a guest. The gaps table below holds it. | `machine-guest-linux`: the guest reports `sys_vendor=QEMU` and `product_name=QEMU Virtual Machine`, and the detector reports `Medium`, `the firmware names the machine QEMU`, and the operation is denied. A second monitor covers the other source: an ARM64 Linux guest under the Apple hypervisor, which OrbStack runs, exposes no `/sys/class/dmi` at all and holds twelve virtio devices, and the same binary there reports `Medium`, `the kernel holds a virtio device, which needs a monitor to answer it`. That arm is manual, because it needs a container runtime that the guest set does not hold. |
| `emulation` | `virtualization.machine_host` | Windows | Windows 11 Pro, build 10.0.26200, ARM64, in the QEMU guest, 2026-08-19 | none. This project owns no bare-metal Windows, and every Windows control runs in the guest. The gaps table below holds it. | `machine-guest-windows`: `GetSystemFirmwareTable` with the `RSMB` provider returns a 383-byte table whose System Information structure names `QEMU` and `QEMU Virtual Machine`, and the detector reports `Medium`, `the firmware names the machine QEMU`, and the operation is denied. The captured table is the fixture that the reader tests against. |
| `emulation` | `virtualization.machine_host` | Android | Android 37, emulator, 2026-08-19 | none. This project owns no physical Android device, and both system images are emulators. The gaps table below holds it. | `machine-emulator-android`: the image reports `ro.boot.qemu=1`, `ro.build.characteristics=emulator`, and `ro.hardware=ranchu`, and the detector reports `Medium`, `the bootloader reports ro.boot.qemu=1`, and the operation is denied |
| `device` | `device_compromise.system_build` | Android | Android 36 and 37, emulators | a Play Store system image, which reports `release-keys` and `ro.debuggable=0`, and stays clean | a Google APIs system image, which reports `dev-keys` and `ro.debuggable=1`, and reports, `Medium` |
| none, the host reports | `ui_abuse.host_report` | any | macOS 26 and ARM64, 2026-08-19 | `interface-clean`: a runtime that no host reported to leaves the slot at `NotRun`, which states the absence of a report, and the operation is allowed | `interface-overlay`: one call to `report_ui_abuse(UiObservation::Overlay)` reports `Medium`, `the host reports that another application drew over its window`, and the operation is denied before the call returns. Both halves run on any machine, because no operating system answers this category. [Detectors and platforms](../../docs/plan/04-detectors-and-platforms.md#the-user-interface) holds the measurement that decided that. |
| `lifecycle` | none | macOS | macOS 26 | a prepared worker thread reports the utility class, and an untouched thread does not | none. The capability reports no finding, so it has no hostile control. |
| `lifecycle` | none | iOS | iOS 26, simulator | the same two controls, in the simulator | none. The capability reports no finding, so it has no hostile control. |
| `lifecycle` | none | Android | Android 37, emulator | an instrumented test attaches a thread the machine has never seen, both from a host handle and by discovery, and a shell binary that runs no machine reports that gap | none. The capability reports no finding, so it has no hostile control. |

## The second architecture

Every row above ran on ARM64. Windows answers for x86_64 on this same machine, because an ARM64
Windows runs an x64 image under its own emulation. That is not an x86_64 machine, and the
[gaps](#gaps) table still asks for one, but it is a real x86_64 process, so the probe walks an
x86_64 address space and reads an x86_64 image. Windows supports both architectures, so this is a
supported configuration. Measured on 2026-08-18, in the QEMU guest:

| Detector | Windows, x64 emulation |
|---|---|
| `integrity.platform_trust` | `Medium`, the image carries no Authenticode signature, which is what an unsigned ARM64 build reports as well |
| `integrity.runtime_baseline` | clean over 40 s |
| `debugging.tracer_present` | clean |
| `instrumentation.unaccounted_code` | **`Medium` on every clean run.** See below. |

**The x64 emulator of Windows trips `unaccounted_code`, and nothing is wrong with the process.** An
x64 build of the `tracer` example reports 1052672 bytes across 4 regions, the same figure on every
run, and the ARM64 build of it reports clean on the same guest. The translator writes code that no
file backs, which is exactly what a manual mapper does. This is the Windows half of the limit that
a warmed Node process states on Linux, and
[detectors and platforms](../../docs/plan/04-detectors-and-platforms.md#unaccounted-code) records it.
The runtime baseline stays clean in that same process, so the two detectors separate cleanly: the
translator maps its cache before `start()` reads the baseline, and it adds no region afterwards.

A translated process costs more, and it pays for the address-space walk rather than for the identity
read. `cost-windows-x86` measures it, and
[state and budgets](../../docs/plan/07-state-and-budgets.md#measured-cost) holds the numbers.

### What macOS on x86_64 showed, before it left the scope

Rosetta runs an x86_64 image on Apple Silicon, and seven controls ran and passed that way on
2026-08-18. macOS then moved to ARM64 alone, because no Intel Mac is in scope, so those controls
left the harness and these two findings are notes rather than recorded results.

**One machine gave `platform_trust` two different reasons, and the kernel decided which.** Apple
Silicon refuses to run an ARM64 image that carries no signature, so the linker gives every local
ARM64 build an ad-hoc one, and `SecCodeCheckValidity` answers -67050, which is a failed requirement.
An x86_64 image needs no signature, so a local x86_64 build carried none, and the same call answered
-67062, which is unsigned. Both reached `Medium` and `ImageUntrusted`, and each stated its own
reason. The ARM64 half of that pair is still live, and the harness still proves it.

**Rosetta tripped nothing.** The baseline stayed clean over 40 s, an injected 64 KiB was still
caught after 5.6 s, and both `lldb` forms still worked. Only the cost moved: `code_regions` took
429 us against 58 us native, because the walk is a loop of system calls.

## Late legitimate loads

These decided two strengths, so they sit apart from the table above. A clean control that reports a
finding is a false positive, and it is worth more than one that stays quiet.

| System | Legitimate action | Regions added | Detector |
|---|---|---|---|
| macOS | `dlopen` of a plugin on disk | 1 | reports `Medium` after 5.7 s |
| macOS | `dlopen` of a library the dyld shared cache holds | 0 | stays clean |
| macOS | a host creates a `WKWebView` | 4 | reports |
| macOS | that view navigates, and runs a JavaScript hot loop | 0 | stays clean |
| macOS | in-process JavaScriptCore, warmed | 0 | stays clean |
| Linux | `dlopen` of a system library, and of a plugin | 1 each | reports `Medium` after 6.5 s |
| Linux | a warmed Node process, for `unaccounted_code` | 1 anonymous, and writable | reports |
| Android | a warmed runtime, for `unaccounted_code` | 0 anonymous, the caches are named | stays clean |

`run.sh` drives the three `dlopen` rows on every run, and it asserts the region counts rather than
printing them. The pair that decided the strength is the pair that now fails a release: a plugin on
disk adds one region and reports, and a cached library adds none and stays quiet for 40 seconds. A
change that made the second one report would be a false positive on the most common benign action
there is, and it would no longer pass in silence.

Two conclusions, and both are now in
[detectors and platforms](../../docs/plan/04-detectors-and-platforms.md):

- `High` is **closed** on `integrity.runtime_baseline` and on `instrumentation.unaccounted_code`,
  rather than pending. A benign explanation that is common cannot support `High`, and loading a
  plugin is common. The finding carries the evidence that the hostile control produces, so nothing
  separates the two.
- A host that embeds a web view creates the view before it calls `start()`. The cost lands once, at
  creation, and no later navigation reports.

Three negative results carry the same weight as the rows above, and
[detectors and platforms](../../docs/plan/04-detectors-and-platforms.md) records each one in its
excluded-mechanisms table: the macOS hardened runtime refuses `DYLD_INSERT_LIBRARIES`, a later
`dlopen` leaves the dyld image list in order, and no absolute count of unattributed executable
memory works on Apple, because a clean process holds about 3.6 GB of it across 13 to 16 regions.

## macOS image identity, all five arms

[Verification](../../docs/plan/05-verification.md) asks for five controls where the host pins a signer.
The harness runs three of them, and a person runs the two that need a certificate, because the
harness must not depend on a private keychain. Measured on 2026-08-18, on macOS 26 and ARM64, with a
Developer ID Application certificate and an Apple Development certificate that carry one team OU and
two different UIDs.

| Arm | How | `platform_trust` | `expected_identity` |
|---|---|---|---|
| a distributed image | signed with the Developer ID certificate, pinned to its own team | clean | clean |
| a locally built image | the ad-hoc signature that the linker writes, pinned to its own cdhash | `Medium`, -67050 | clean |
| a repackaged image | a copy re-signed under another identifier, against the original cdhash | `Medium`, -67050 | `High` |
| a second certificate of one team | signed with the Apple Development certificate, against that same team requirement | clean | clean |
| a distributed image, pinned to another signer | the Developer ID image, against a team it does not carry | clean | `High` |

The last two arms are the pair that matters, and they answer opposite ways on purpose. The fourth
changes the certificate and stays clean, because the requirement names a team rather than a
certificate. The fifth keeps the certificate and reports, because the team is wrong. That pair is
what proves the two tiers ask different questions.

The first arm is the only control anywhere in this record where `integrity.platform_trust` accepts
an image. Every other platform-trust row in the table above is a rejection or an `Unsupported`.

Reproduce it with your own certificate. The team is the `OU` field of the signing certificate, which
`security find-identity -v -p codesigning` lists and `openssl x509 -noout -subject` prints:

```sh
cargo build --example identity -p fidelity
codesign -f -s "Developer ID Application: YOUR NAME (TEAMID)" -o runtime \
    target/debug/examples/identity
target/debug/examples/identity \
    'anchor apple generic and certificate leaf[subject.OU] = "TEAMID"'
```


## Guarded constants and code identity

`guarded!()` derives its key from the per-build salt and the code identity that the operating system
reports. Measured on 2026-08-09: a build that named an identity, on an image that reports none, gave
a wrong value from every guarded constant and reported nothing at all.

| Build states | System | Image | With no check | Today |
|---|---|---|---|---|
| `apple:ABCDE12345` | macOS 26 | signed ad hoc, by Cargo | `host: p\I{uc7f*Kbuuia` | the start fails, typed |
| `apple:ABCDE12345` | Debian, glibc | unsigned | `host: p\I{uc7f*Kbuuia` | the build fails, and the next section says why |
| `none` | both | any | `host: api.example.com` | unchanged |

The macOS row matters most, because macOS is the platform whose probe answers. Cargo signs a local
build ad hoc, an ad-hoc signature names no team, so an ordinary `cargo run` reached this. `start()`
now returns `StartError::IdentityBindingUnavailable`, which names the reason and both answers to it.

**A second silent failure sat behind the first, and only Android reached it.** Measured on
2026-08-10: the Android probe reported the signing certificate digest as 32 raw bytes, and a build
states its identity in a variable that carries a string. No string holds those bytes, so a bound
Android build could not be made at all, and every guarded constant in it would have decrypted to
garbage while `start()` succeeded. The probe now reports the digest as lowercase hexadecimal, which
is the form that `keytool -list -v` and `apksigner` already print.
`Signer::material` states the rule, and two tests in the Android probe hold it: one proves the raw
digest is not text, and one proves the hexadecimal form is. The `PackageManager` cross-check still
agrees, so the change cost no accuracy.

Two limits came out of the same measurement, and
[ADR-0007](../../docs/adr/0007-value-producing-check.md) records both. Both key inputs ship inside the
artifact, so the guard resists a repackage and not an offline extraction. One build-time value
cannot serve two platforms, because each one reports different material.

**A third silent failure sat behind the second, and it took two platforms to see.** The variable
carried a bare value, so an Apple team identifier in an Android build reached the key derivation
and nothing refused it. `start()` succeeded, because the archive does carry a signer. Every guarded
constant then decrypted to a wrong value, and a guarded read reports no error by design. The value
now names the kind of material in front of the material. Measured on 2026-08-11:

| Build states | Target | Result |
|---|---|---|
| `apple:ABCDE12345` | macOS, iOS | builds |
| `android:` and 64 lowercase hexadecimal digits | Android | builds |
| `apple:ABCDE12345` | Android | the build fails, and the message names both kinds |
| `android:` and the same digits | macOS | the build fails, and the message names both kinds |
| `apple:ABCDE12345` | Linux | the build fails, because Linux reports no code identity |
| `ABCDE12345` | any | the build fails, because the value names no kind |

`crates/fidelity/build.rs` holds the check, and it is the only place that can. Cargo states
`CARGO_CFG_TARGET_OS` to a build script and to nothing else, and the macro expands in the host
crate, where that name is absent. `fidelity-cipher/src/binding.rs` holds the parser that the build
script and the macro both call, so the two never disagree about one value, and 13 unit tests hold
its rules. Each rule was broken on purpose against a real build, and each one failed as it should.

The Android form is checked exactly, because `keytool -list -v` prints two traps side by side. It
separates every pair of digits with a colon, and the first pair then reads as the kind. It also
prints a SHA-1 digest one line above the SHA-256 digest, and the shorter line is the easier line to
copy. The Apple form is checked for whitespace only, because this project has not verified which
characters a team identifier holds.

End to end on Android 37, on the emulator: Gradle now passes `android:` with the debug certificate
digest, the instrumented suite stays at 8 of 8, the guarded constant still reads `6170692e`, and
`controls/repackage-android.sh` still gives another value, `79332e2d`, with no error.

## Cost

[State and budgets](../../docs/plan/07-state-and-budgets.md) holds the numbers and the ceiling. Every
one came from `cargo run --release --example cost` in the probe crate of the platform, on
2026-08-10, on ARM64, with the shared loop in `crates/probe/measure.rs`.

Two results changed how the budget reads, and both came from the measurement rather than from the
design:

- **A read that touches static memory only measures nothing in a loop.** The first iOS run reported
  84 ns for the identity read, and the optimizer had lifted the whole call out. Every example now
  reads through `&dyn Environment`, behind `black_box`. That is also the call the engine makes, so
  the number and the shape both improved. The iOS figure stayed at 84 ns, because the walk really
  does stop at the missing entitlements slot, and `otool -l` confirms the image carries a
  signature of 3664 bytes with no entitlements.
- **A shell binary cannot measure Android.** It maps no archive, so its identity read stops at the
  gap after 52 us. The instrumented harness measures an application process instead: 542 us for one
  identity read, and 2.5 ms for one worker cycle. The cycle is 14 times the shell figure, because a
  real application maps far more regions and two reads walk the whole mapping table.

The Android ceilings are a test rather than a note.
`HarnessTest.the_identity_read_stays_inside_its_recorded_ceiling` fails above 4 ms for one identity
read or 9 ms for one cycle. Both hold about four times the measured value, because an emulator
under test is not a quiet machine. The rule was broken on purpose and it failed as it should.

## The extraction gate

[Verification](../../docs/plan/05-verification.md) requires two results from this pair of controls, and
both ran on 2026-08-11. The first records a ceiling. The second proves the property that the design
does promise.

**The ceiling: one extractor reads every guarded constant offline.**
`cargo run --release --example extract -p fidelity-cipher` takes a built binary and the code
identity, which is public, and it knows no seed. Against `--example guarded` on macOS 26 and ARM64:

| Input | Result |
|---|---|
| the correct identity | both constants recovered, in 40 s |
| a wrong identity | both stayed hidden, and the control exits non-zero |
| `strings` on the same binary | the plaintext appears 0 times |

The last two rows matter as much as the first. They prove the extractor derives the values rather
than reading them, so the ceiling is real and the control is not measuring itself.

Two measured facts describe the cost, and neither is a defense:

- The salt and the ciphertext both ship in the constant pool, and the compiler orders that pool by
  size rather than by expansion. One constant put its ciphertext 16 bytes in front of its salt, and
  another put it 1346 bytes behind. A blind search therefore tries 2.1 thousand million pairs.
- The stream is alphabet-preserving, so every wrong key also gives printable text. Printability
  filters nothing, and a blind search returns about 34 million candidates that hold the two real
  ones. The count falls by about 0.7 for each added character, which is what a filter of 66
  acceptable characters in 95 predicts, so the noise carries no signal either.

Neither cost stops an attacker who disassembles one call site. `__guarded` is inlined, so the call
site loads both addresses, and reading them removes the search. Treat 40 s as an upper bound.

**The promise: another signer gives another value, and nothing reports it.**
`controls/repackage-android.sh` signs the instrumented test archive with a second key, installs that
copy, and reads the same guarded constant. Measured on Android 37, on the emulator:

| Archive | Guarded value, first four bytes |
|---|---|
| the archive that the build named | `6170692e`, which is `api.` |
| the same archive, signed by another key | `512d6662` |

`start()` succeeded in both. The repackaged archive carries a signer, so nothing fails, and the
value simply changes. That is the design: a value rather than a decision, and no branch to invert.
`HarnessTest.a_guarded_constant_returns_its_literal_in_the_archive_that_the_build_named` holds the
clean half, so a regression fails a test.

This is the first `start()` inside a real Android application. Gradle reads the debug keystore,
computes the certificate digest, and passes it as `FIDELITY_CODE_IDENTITY`, so the build binds to
the archive that AGP signs. A hard-coded digest would fail on every other machine.

## Sanitizers and Miri

Run with `controls/run-sanitizers.sh`. Results on macOS 26 and ARM64, on 2026-08-09:

| Tool | Scope | Result |
|---|---|---|
| AddressSanitizer | the whole workspace, 292 tests | clean |
| ThreadSanitizer | the whole workspace, 292 tests | clean |
| Miri | the seven crates that forbid unsafe code, 265 tests, 3 m 40 s | clean, on 2026-08-13 |

**Miri had never run as the script described it.** The row above said 30 tests in one crate, and the
script named seven. Measured on 2026-08-13: the script failed on the first crate that reads a clock,
because `SystemTime::now` asks for a real-time clock and Miri refuses one under isolation. It also
never finished `fidelity-cipher`, whose tests hash a long message and sweep 100000 wrong keys, which
an interpreter cannot do. The script now disables isolation, and it excludes those three tests by
name rather than dropping the crate, which keeps 28 of its tests at a cost of five seconds. The
whole set is 265 tests, and `fidelity-formats` alone is 78 of them, so the old row understated the
scope as well as the state.

**AddressSanitizer earned its place on the first run, and not by finding a memory bug.** It failed
`two_reads_of_an_unchanged_process_add_no_region`, which asserts that two reads of a quiet process
report the same regions. The test passed alone and failed in the full suite, so the sanitizer had
changed the timing rather than found a defect in the walk: a concurrent test mapped 112 KiB of
executable memory between the two reads.

The test was therefore order dependent, and it had been passing by luck. It guards the property that
stops the baseline detector reporting on every cycle, so a flake there is worth more than a small
memory bug. It and its two siblings now take up to eight pairs of reads and require one pair to
agree. A walk that really moved would never produce an agreeing pair, so the bound still fails a
broken walk. Confirmed by three consecutive clean sanitizer runs.

Two limits are structural, not oversights. Miri cannot cross a foreign call, so it never reaches a
probe crate, and the sanitizers are what cover the `unsafe` there. A doc-test cannot link under a
sanitizer, because rustdoc omits the runtime, so the script excludes doc-tests and `cargo test
--workspace` runs them instead.

## The diagnostics test, and what made it flake

`run.sh` reported one failure on 2026-08-19, in
`worker::diagnostics::a_qualifying_finding_reaches_the_subscriber_that_the_host_installed`. The
test passed by itself and under every ordinary run, so the first job was to reproduce it rather
than explain it. The engine test binary, run 40 times at each of five thread counts, failed 2 times
in 40 at 16 threads and never once at 1 thread.

The cause is in `tracing` and not in the engine. `tracing` caches whether a call site is enabled the
first time any thread reaches it, and that decision reads the subscribers a host installed for the
whole process. A subscriber that one test installs for its own thread is invisible to it. So a test
that reaches `record()` first can cache "this site is never enabled", and the diagnostics test then
sees no event at all. A single thread never fails, because the diagnostics test sorts before every
other test in that module and reaches the site first.

The fix installs a process-wide subscriber that enables every call site and counts nothing, so the
scoped counter still measures one worker. Three variants ran at 16 threads: no fix failed 5 times in
200, `rebuild_interest_cache` alone failed 3 times in 100, and the process-wide subscriber alone
failed none in 150. The rebuild is therefore not the fix, and the code does not call it.

## The generated record

`run.sh` ran the whole set on 2026-08-19, on macOS 26 and ARM64, with a booted iOS simulator, both
guests running, and an Android 37 emulator attached. It wrote 102 rows: 97 passed, 4 `manual`, 1
skipped, and none failed. The skipped row is Miri, which keeps its own schedule. A run takes about
13 minutes, or 16 with `FIDELITY_WITH_MIRI=1`. Nine clean controls spend 40 seconds each waiting for
a finding that must never arrive.

Sixty-one of the 94 are the hostile controls and their clean halves, which used to need a person.
Each `caught after` figure is the time a host is exposed for, and it is the number that matters
most. A macOS or a Linux row below holds two runs, because the worker interval carries jitter and a
single figure would read as a constant:

| Control | System | Answer |
|---|---|---|
| `identity-clean-macos` | macOS | the image, pinned to its own cdhash, stays clean |
| `identity-repackaged-macos` | macOS | a copy re-signed under another identifier, against the original cdhash, reported `High` |
| `identity-pinned-other-macos` | macOS | the same image against a team it does not carry, reported `High` |
| `identity-adhoc-macos` | macOS | the ad-hoc signature that the linker writes fails `anchor apple generic`, `Medium`, -67050 |
| `baseline-hostile` | macOS | `delayed.c` maps 64 KiB after start, caught after 5.6 s and 7.1 s |
| `baseline-clean` | macOS | 40 s with no finding |
| `tracer-at-start` | macOS | `lldb -b` runs the whole program, found by the initial scan |
| `tracer-attaches` | macOS | `lldb -p` attaches after start, caught after 5.4 s and 5.8 s |
| `tracer-clean` | macOS | a run with no debugger |
| `identity-clean-ios` | iOS | an ad-hoc build names no team, and an absent host value allows the operation |
| `identity-pinned-team-ios` | iOS | a pinned team, against that same image, reported `High` and denied the operation |
| `tracer-at-start-ios` | iOS | `lldb -b` launches the simulator binary itself, found by the initial scan |
| `tracer-attaches-ios` | iOS | `lldb -p` attaches after start, caught after 5.5 s |
| `tracer-clean-ios` | iOS | a run with no debugger |
| `baseline-hostile-ios` | iOS | `delayed.c` maps 64 KiB after start, caught after 5.7 s |
| `baseline-clean-ios` | iOS | 40 s with no finding |
| `baseline-hostile-linux` | Linux | the same agent, caught after 6.1 s and 6.8 s |
| `baseline-clean-linux` | Linux | 40 s with no finding |
| `inject-hostile` | Linux | `agent.c` maps 4 KiB, reported, and the operation denied |
| `inject-clean` | Linux | a loader that maps a library from a file reports nothing |
| `dispatch-hostile-linux` | Linux | `hook.c` points `memcpy` at `memmove`, caught after 5.6 s, `Medium` |
| `dispatch-clean-linux` | Linux | 40 s with no finding, and the baseline stays clean too |
| `tracer-at-start-linux` | Linux | `attach.c` traces from exec, found by the initial scan |
| `tracer-attaches-linux` | Linux | `attach.c` attaches after start, caught after 5.3 s and 5.8 s |
| `tracer-clean-linux` | Linux | a run with no tracer |
| `identity-clean-linux` | Linux | the image, pinned to the digest of its own content, stays clean |
| `identity-repackaged-linux` | Linux | the same image with one byte appended, reported `High` |
| `verity-linux` | Linux | an ext4 filesystem made with `-O verity` reports `Accepted`, and an ordinary one reports `Unsupported` |
| `baseline-hostile-windows` | Windows | `inject-windows.c` maps 64 KiB after start, caught after 5.3 s |
| `baseline-clean-windows` | Windows | 40 s with no addition |
| `inject-hostile-windows` | Windows | `inject-windows.c` maps 64 KiB with no file behind it, reported, and the operation denied |
| `inject-clean-windows` | Windows | a plain run accounts for every executable region it holds |
| `dispatch-hostile-windows` | Windows | `iat-hook-windows.c` redirects an import, caught after 7.0 s, `Medium` |
| `dispatch-clean-windows` | Windows | 40 s with no finding, and the baseline stays clean too |
| `tracer-at-start-windows` | Windows | `attach-windows.c` traces the subject from the start, found by the initial scan |
| `tracer-attaches-windows` | Windows | `attach-windows.c` attaches after start, caught after 6.1 s |
| `tracer-clean-windows` | Windows | a run with no debugger |
| `identity-clean-windows` | Windows | a signed copy, pinned to the SHA-256 of its own signer, stays clean |
| `identity-other-signer-windows` | Windows | the same copy, pinned to another certificate, reported `High`, and the operation denied |
| `identity-untrusted-windows` | Windows | a copy that nothing anchors, where both tiers report together |
| `inject-emulated-x86` | Windows | a clean x64 process reports 1052672 bytes across 4 regions, `Medium` |
| `baseline-clean-x86-windows` | Windows | 40 s with no addition, in that same x64 process |
| `tracer-clean-x86-windows` | Windows | a run with no debugger, in that same x64 process |
| `plugin-load` | macOS | 1 region before, `+0` for a cached library, `+1` for a plugin |
| `plugin-load-linux` | Linux | 4 mappings before, `+1` for `libm`, `+1` for a plugin |
| `legitimate-plugin` / `-linux` | macOS, Linux | a host loads its own plugin after start, reported after 7.1 s and 5.6 s |
| `legitimate-cached` | macOS | a host loads a cached library after start, 40 s with no finding |
| `tracer-at-start-android` | Android | `attach.c`, built with the NDK, traces from exec, found by the initial scan |
| `tracer-attaches-android` | Android | the same tool attaches after start, caught after 6.3 s |
| `tracer-clean-android` | Android | a run with no tracer |
| `baseline-hostile-android` | Android | `delayed.c` maps 64 KiB after start, caught after 6.8 s |
| `baseline-clean-android` | Android | 40 s with no finding |
| `inject-hostile-android` | Android | `agent.c` maps 16 KiB with no file behind it, reported `Medium` |
| `inject-clean-android` | Android | a plain run accounts for every executable region it holds |
| `android-identity-mechanism` | Android | the keystore and a walk of the signing block report one digest |

The record is checked in, so `run.sh` removes the path of the workspace from every detail. A record
that named one machine could not be compared against a run on another.

**The harness earned its place on its first run, and not by confirming a result.** Two Android rows
failed, and the reason sat in this file rather than in the code. The recorded recipe never set
`CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER`. Cargo links an Android binary with `cc`, which is the
host compiler on this machine, and the Apple linker refuses the arguments that Cargo passes. Every
earlier Android run happened in a shell that already exported the name, so the recipe had never
been read by anything except a person who already knew the answer. That is the exact failure a
generated record exists to catch: a control that only works for the person who wrote it down. The
harness now finds the NDK linker itself, and it records a `skipped` row when it finds none.

**A run with no limit hid a stall for 12 hours.** `android-instrumented` once stopped answering, and
the harness waited on it rather than reporting anything at all. Every control now runs under a
watchdog that kills it after 900 seconds and writes a `fail` row that says so. A base macOS carries
no `timeout`, so the watchdog is plain shell, and it kills the descendants as well, because the
control that hangs is usually a grandchild. The stall itself has no proven cause. It has not
returned since, and the emulator now runs with `-gpu host` rather than a software renderer, which is
one candidate and not an answer. Measured on 2026-08-18: the same control finishes in 29 seconds.

**A control that nobody compiles stops compiling.** `attach.c` held its build command in its own
header comment, and that command named an NDK directory with a star and a slash in it. Those two
characters close a C comment, so the file had not compiled since the line landed. The comment now
carries the rule that a path in a comment holds no glob, and the harness compiles the file on every
run.

**A version that nothing builds is a claim, not a pin.** `Cargo.toml` names 1.85 as the minimum
Rust version, and [delivery](../../docs/plan/06-delivery.md) makes that normative. Measured on
2026-08-13: the workspace did not build on 1.85 at all. Two `let` chains had landed, and that
syntax needs 1.88. Both are now written the older way, all five targets build on 1.85, and the
harness builds the pinned version on every run. It reads the version out of the manifest, so the
check and the claim cannot separate again.

## Controls

`controls/` holds the source of every hostile control. Each one is small on purpose: a control that
needs reading is a control that nobody re-runs.

| File | Produces |
|---|---|
| `run.sh` | the generated record, `record.tsv`. It drives every control below that gives an answer on its own, and it writes a `manual` row for each one that needs a person. |
| `controls/agent.c` | unaccounted code. It maps 4 KiB of anonymous executable memory at load. |
| `controls/delayed.c` | a runtime baseline finding. It waits 3 s, then maps 64 KiB, so the mapping arrives after `start()` captured the baseline. |
| `controls/hook.c` | a dispatch redirect. It waits 3 s, then rewrites one entry of the main image's dispatch table so a call reaches another function that already exists. The inside form points `memcpy` at `memmove`, which answers every call, so the subject keeps running and no new region maps. Its shared loader walk is in `controls/dispatch.h`. |
| `controls/dispatch.h` | the dispatch-target walk, in C, so a control reads the table without linking the library. `controls/regions.h` does the same job for the Mach region walk. |
| `controls/iat-hook-windows.c` | the Windows dispatch redirect. It opens a running subject by process identifier, finds a startup-only import of the main module, and redirects it with `WriteProcessMemory` to an address that another import already holds. The import sits in a data section, so no region maps and the runtime baseline stays clean. |
| `controls/attach.c` | a tracer finding where no debugger is available. It is a minimal `ptrace` tracer, in two forms: it traces a program from its own exec, or it attaches to a process that already runs. |
| `controls/trace-after-start.sh` | the tracer control that only the worker can catch. It starts the `attach` example, reads the process identifier that the example prints, and puts a tracer on it. `lldb -p` is the tracer on macOS and on iOS, `attach.c` is the tracer on Linux and on Android, and `attach-windows.c` is the tracer on Windows. On iOS the harness gives it a two-line wrapper, because the subject runs inside the simulator and this script takes one command with no argument. |
| `controls/legitimate.c` | the clean control that decided the runtime baseline strength. The host loads one of its own plugins after start, and the detector reports it. |
| `controls/phases.m` | the web-view measurement, split into creation, first navigation, and later navigation. |
| `controls/plugin-load.c` | the macOS region counts behind the runtime-baseline strength: a cached library adds none, a plugin adds one. |
| `controls/plugin-load-linux.c` | the same measurement on Linux, where a system library also adds one. |
| `controls/qos-drift.c` | the wake-drift measurement that chose utility over background for the Apple worker. |
| `controls/make-apk.sh` | the Android identity mechanism. It signs a small archive, reads the certificate digest from the keystore and from a walk of the signing block, and fails when the two disagree. Each run makes a fresh key, so the digest changes and only the agreement repeats. It made the recorded archive that `fidelity-formats` tests against, and it needs no device. |
| `controls/entitle.c` | the iOS identity mechanism, in C. It finds the code signature of the running image and prints the entitlements, so the boundary can be checked without the library. It also produced the two recorded signatures that `fidelity-formats` tests against. |
| `controls/regions.h` | the Mach region walk, in C, so a control can count regions without linking the library. |
| `controls/run-sanitizers.sh` | the unsafe-wrapper test layer: both sanitizers, and Miri when asked. |
| the `cost` example of each probe crate | the cost of every capability read, for the budget. It is an example and not a control, because it produces a number rather than a finding. |
| `controls/repackage-android.sh` | the repackage half of the extraction gate. It signs the instrumented test archive with a second key, reads the same guarded constant, and restores the original archive. |
| the `extract` example of `fidelity-cipher` | the ceiling half. It reads guarded constants out of a built binary with no secret but the public code identity. |
| `controls/run-ios.sh` | the runner that `cargo test --target aarch64-apple-ios-sim` needs. |
| `controls/run-android.sh` | the runner that `cargo test --target aarch64-linux-android` needs. |

Each runner takes one test binary and runs it on its system, which is the shape
`CARGO_TARGET_<TARGET>_RUNNER` expects.

## How to reproduce

### Everything that this machine can reach

The cross-check builds nine targets, and the minimum-version control builds the same nine on the
older toolchain. `rustup target add` works on one toolchain at a time, so both lines are necessary.
A missing target fails as `can't find crate for std`, which names the target and not the toolchain:

```sh
TARGETS="aarch64-apple-darwin aarch64-apple-ios \
    aarch64-linux-android x86_64-linux-android \
    aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu \
    aarch64-pc-windows-msvc x86_64-pc-windows-msvc"
rustup target add $TARGETS
rustup target add --toolchain "$(sed -n 's/^rust-version = "\(.*\)"$/\1/p' Cargo.toml)" $TARGETS
tests/platform/run.sh
```

It writes `record.tsv`, and it leaves the output of each control under `target/platform/`. Each
section below sets up one system that the harness reports as skipped, so boot a simulator, start a
guest, or attach a device, and run it again.

### iOS, on the simulator

```sh
xcrun simctl boot "iPhone 16 Pro"
export FIDELITY_IOS_SIM=$(xcrun simctl list devices | awk '/Booted/ {print $(NF-1)}' | tr -d '()')
export CARGO_TARGET_AARCH64_APPLE_IOS_SIM_RUNNER=$PWD/tests/platform/controls/run-ios.sh
cargo test -p fidelity-probe-apple --target aarch64-apple-ios-sim

# The hostile control for the baseline.
SDK=$(xcrun --sdk iphonesimulator --show-sdk-path)
clang -arch arm64 -isysroot "$SDK" -mios-simulator-version-min=18.0 \
    -dynamiclib -o /tmp/delayed.dylib tests/platform/controls/delayed.c
cargo build --example late --target aarch64-apple-ios-sim
SIMCTL_CHILD_DYLD_INSERT_LIBRARIES=/tmp/delayed.dylib xcrun simctl spawn "$FIDELITY_IOS_SIM" \
    "$PWD/target/aarch64-apple-ios-sim/debug/examples/late"

# The hostile control for the tracer. Attach to the process identifier it prints.
cargo build --example attach --target aarch64-apple-ios-sim
xcrun simctl spawn "$FIDELITY_IOS_SIM" "$PWD/target/aarch64-apple-ios-sim/debug/examples/attach" &
( echo continue; sleep 25 ) | lldb -p <pid>
```

`lldb` runs on the host and attaches across the simulator boundary, because a simulator process is
a host process.

### Guarded constants, on any platform

```sh
FIDELITY_BUILD_SEED=test FIDELITY_CODE_IDENTITY=apple:ABCDE12345 cargo run --example guarded
FIDELITY_BUILD_SEED=test FIDELITY_CODE_IDENTITY=none             cargo run --example guarded

# The platform check. Every line below fails the build, and each message names the answer.
FIDELITY_BUILD_SEED=test FIDELITY_CODE_IDENTITY=ABCDE12345 cargo check -p fidelity
FIDELITY_BUILD_SEED=test FIDELITY_CODE_IDENTITY=apple:ABCDE12345 \
    cargo check -p fidelity --target aarch64-linux-android
FIDELITY_BUILD_SEED=test FIDELITY_CODE_IDENTITY=apple:ABCDE12345 \
    cargo check -p fidelity --target aarch64-unknown-linux-gnu
```

The first fails the start, and the second prints the two literals. A build script reads the
variable, so Cargo re-expands and re-checks whenever it changes.

### The cost measurement, on each system

Each line needs the environment that its own section below sets up. Release mode matters, because
that is what a host ships.

```sh
cargo run --release --example cost -p fidelity-probe-apple
cargo run --release --example cost -p fidelity-probe-apple  --target aarch64-apple-ios-sim
cargo run --release --example cost -p fidelity-probe-linux            # inside the guest
cargo run --release --example cost -p fidelity-probe-windows          # inside the guest
cargo run --release --example cost -p fidelity-probe-android --target aarch64-linux-android
```

The Android line measures a shell binary, which maps no archive. `./gradlew
connectedDebugAndroidTest` measures an application process, and it prints both numbers to logcat
under the `fidelity` tag.

### The second architecture

This needs no second machine. The Windows guest answers through the x64 emulation that an ARM64
Windows already carries:

```sh
tests/platform/controls/vm.sh windows run 'cd /c/work &&
    rustup target add x86_64-pc-windows-msvc &&
    cargo run --quiet --example tracer -p fidelity --target x86_64-pc-windows-msvc'
```

Read what it reports. It says `unaccounted_code: Medium` on a process that did nothing wrong, and
the ARM64 build in the same guest reports clean.

macOS needs no line here. It runs on ARM64 alone, so Rosetta answers for nothing that this project
promises. The [note above](#what-macos-on-x86_64-showed-before-it-left-the-scope) keeps what it
showed while it was in scope.

### Linux, in the guest

```sh
tests/platform/controls/vm.sh linux build       # Packer, once, and it asks nothing
tests/platform/controls/vm.sh linux start       # about 20 s
tests/platform/controls/vm.sh linux run 'uname -a'
```

Packer builds the image from `tests/platform/vm/linux/`, and that build is the whole
setup: the install, the account, the toolchain, and the key. `start` boots a
copy-on-write overlay on top of that image, so a run never dirties it, and
`reset` throws the overlay away, so a pristine guest costs seconds. A build
that produces a newer image drops a stale overlay by itself.

A container ran these controls before, and it could not answer two of them. It
shares the kernel of the machine that hosts it, so it holds no filesystem of
its own and fs-verity cannot be enabled there, which left the platform-trust
tier with nothing to report. It also needed `--cap-add=SYS_PTRACE`, so every
tracer control ran under a grant that no real host gives itself.

The workspace arrives over 9p at `/work`, which is where the container mounted
it, so a control reads one path either way. The build directory stays on the
disk of the guest, at `/var/tmp/target`: the host and the guest otherwise fight
over one `target/`, and a build over a shared filesystem is far slower.

A machine that already runs Linux needs none of this. `run.sh` runs the same
control text on that machine directly, and only the place changes.

#### The second Linux arm of the machine host

`machine-guest-linux` reads the firmware name, and this arm reads the other
source. A person runs it, because it needs a second monitor that the guest set
does not hold. Any container runtime that boots a Linux guest under the Apple
hypervisor supplies one, and OrbStack is what ran it here:

```sh
tests/platform/controls/vm.sh linux run \
    'cd /work && . $HOME/.cargo/env && cargo build --quiet --example machine -p fidelity'
tests/platform/controls/vm.sh linux run \
    'base64 -w0 /var/tmp/target/debug/examples/machine' | base64 -d > /tmp/machine-linux
chmod 755 /tmp/machine-linux
docker run --rm -v /tmp:/probe:ro debian:bookworm-slim /probe/machine-linux
```

The guest builds the binary, because the Mac holds no Linux linker. Measured on
2026-08-19: that guest exposes no `/sys/class/dmi` at all and lists twelve
virtio devices, and the detector reported `Medium`, `the kernel holds a virtio
device, which needs a monitor to answer it`, and denied the operation. The
firmware source says nothing there, so this is the only control that reaches
the paravirtual rule on a live system.

### macOS, in the guest

```sh
tests/platform/controls/vm.sh macos build       # 20 GB download, then a 20 min install
tests/platform/run.sh                           # machine-guest-macos runs by itself
```

This guest exists for one control. `virtualization.machine_host` reads what the kernel says about
the machine below it, and only a macOS kernel that runs under a monitor gives the other answer. The
machine itself is the clean control, so the guest is the hostile half of the pair.

It takes a different road from the other two, and QEMU is the reason: QEMU boots no macOS on Apple
Silicon. `tests/platform/vm/macos/guest.swift` drives Virtualization.framework instead, which is the only
interface that does. The tool is one Swift file and it needs no third-party part. It carries the
`com.apple.security.virtualization` entitlement, which an ad-hoc signature grants, so the build
needs no certificate. Without that entitlement every call fails and the catalog reports only
"failed to load", which names no cause.

Three things differ from the Packer guests. Apple serves the restore image to a program, so the
download needs no person, and the framework names the build that this machine can run. An APFS
clone replaces the qcow2 overlay, and it costs no space until the guest writes. And the framework
puts the guest on a shared network, so SSH goes to an address that `/var/db/dhcpd_leases` holds
rather than to a forwarded port. That lease file writes each octet with no leading zero, so
`vm.sh` normalizes both sides before it compares them.

No person answers a window, and that took one measurement to get right. Apple ships no answer file
for the setup assistant, so a fresh guest holds no account and answers no network.
`tests/platform/vm/macos/provision.sh` goes around it: the guest disk is a raw image, the host
mounts its APFS data volume with no privilege, and a launch daemon written there runs the control at
boot, before the assistant appears. The daemon writes its answer to the same disk and powers the
guest off, and the host reads the answer back with `provision.sh <bundle> --read`.

Ownership is the part that looks like a wall. A launch daemon loads only when root owns its plist,
and a file that the host creates lands under the uid of the host user, and a chown to root needs
sudo. A rename inside one volume keeps the inode, and a truncating write keeps it too, so an
existing root-owned plist becomes the new one and stays root-owned. Measured on 2026-08-18.

`vm.sh macos setup` still exists, and it is optional now. Run it only when a control needs a real
session, SSH, or a window. Host and guest take one target triple, so no build runs in the guest and
the guest needs no tool chain either way.

### Windows, in the guest

```sh
tests/platform/controls/vm.sh windows iso       # the one step a person takes
tests/platform/controls/vm.sh windows build     # Packer, 36 min, and it asks nothing
tests/platform/controls/vm.sh windows start
tests/platform/controls/vm.sh windows push      # the workspace, to C:\work
```

The build installs Windows without a person. Windows 11 25H2 boots a Setup
that ignores an answer file on its first pages, so `install.cmd` does the
install that Setup would: it partitions the disk, applies the image with
`dism`, injects the virtio network driver, and writes the boot files. The
answer file then drives the account and the first logon only.

`run.sh` needs no argument for the guest. It finds one, pushes the workspace,
and runs each Windows control there, in the same command text that a Windows
runner would run on itself.

The image is the one step a person takes, and the reason is Microsoft's. Three
of the four download steps answer a script: the page names the ARM64 product,
and an interface returns the language list. The fourth, which turns a language
into a link, refuses with `ErrorSettings.SentinelReject`, because Microsoft
guards that endpoint against automation on purpose. Measured on 2026-08-13.
Working around that guard is not this project's business.

### Android, the instrumented harness

Two Android test paths exist, and they answer different questions. The runner below runs the Rust
unit tests on the device, which covers everything the kernel answers. It cannot reach a Java
interface, because a shell binary has no JVM and no package. The instrumented harness in
`crates/probe/fidelity-probe-android/android/` supplies both, because it runs inside an application
process.

```sh
# `-gpu host` matters. The stall that the timeout note above describes happened
# under the software renderer, and it has not returned under this one.
$ANDROID_HOME/emulator/emulator -avd Pixel_10_Pro_XL -gpu host -no-snapshot-load -no-boot-anim &
adb wait-for-device
cd crates/probe/fidelity-probe-android/android
./gradlew connectedDebugAndroidTest
```

Gradle builds the harness cdylib with cargo first, so no separate Rust step is needed. Two notes
that cost time to find: the wrapper needs a complete Gradle distribution, and a partial download in
`~/.gradle/wrapper/dists` fails with a socket timeout that looks like a network block. The build
needs the network on its first run, because not every transitive test dependency is cached.

### The two Android system images

The `device` capability needs both, and they are the clean control and the hostile control for the
same code. A Play Store image is a production build, which is why the store runs on it. A Google
APIs image is a development build.

```sh
avdmanager create avd -n Fidelity_Play_36 -d pixel_6 \
    -k "system-images;android-36;google_apis_playstore;arm64-v8a"

# Then boot one, and run the detectors against it.
FIDELITY_BUILD_SEED=test FIDELITY_CODE_IDENTITY=none \
    cargo run --example identity -p fidelity --target aarch64-linux-android
```

The Play image prints `device_compromise.system_build: clean`. The Google APIs image prints
`Medium` and names `ro.debuggable=1`. Two notes that cost time: a `google_apis_playstore_ps16k`
image stayed offline through a 17-minute boot, and the plain `google_apis_playstore` image booted
in about 4 minutes. `getprop ro.build.tags` confirms which image is running.

#### What a rooted release build reports

The coverage limit is measured, and it is not an argument. Measured on 2026-08-18, on the Android 36
Play Store image and ARM64:

```sh
git clone --depth 1 https://github.com/newbit1/rootAVD.git
cd rootAVD && ./rootAVD.sh system-images/android-36/google_apis_playstore/arm64-v8a/ramdisk.img
# Then cold boot the AVD, and run the detectors again.
```

Magisk 25.2 installs, the tool patches the ramdisk, and `magiskd` runs as root after the cold boot.
`/system/bin/su` appears, as a symbolic link to `magisk`. The application reports `Ramdisk: Yes`.
The system now holds a root daemon that no vendor shipped.

`ro.build.tags` still reports `release-keys`, `ro.debuggable` still reports 0, and
`device_compromise.system_build` still reports `clean`. Every other detector reports clean as well.
A released-build answer is therefore worth what the plan says it is worth, and no more: the tool
that takes the privilege leaves the two properties alone, so this detector never sees it.

Two limits of this run. Magisk denied `su` to an adb shell that nobody approved, because its own
superuser policy prompts first, so no root shell ran. That changes nothing here, because the
detector reads two properties rather than a privilege. And the tool patches the ramdisk that the
whole SDK shares, so copy `ramdisk.img` before the run. `rootAVD.sh ... restore` puts the stock one
back, and it writes `ramdisk.img.backup` beside it.

### Android, on a device or an emulator

```sh
NDK_CC=$(ls "$ANDROID_HOME"/ndk/*/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android*-clang | tail -1)
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$NDK_CC
export CARGO_TARGET_AARCH64_LINUX_ANDROID_RUNNER=$PWD/tests/platform/controls/run-android.sh
cargo test -p fidelity-probe-android --target aarch64-linux-android
```

### Android, the seven detector controls

`run.sh` runs all seven. They push an example and an agent to `/data/local/tmp/`, and they use the
same sources that Linux uses, because Android keeps the Linux process filesystem and the Linux
loader. Run one by hand this way:

```sh
NDK_CC=$(ls "$ANDROID_HOME"/ndk/*/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android*-clang | tail -1)
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$NDK_CC

# The tracer, in both of its hostile forms. `attach.c` needs no `-lpthread`
# here, because pthread is inside the Android libc.
cargo build --example tracer --example attach -p fidelity --target aarch64-linux-android
"$NDK_CC" -o /tmp/attach-tool tests/platform/controls/attach.c
adb push target/aarch64-linux-android/debug/examples/tracer /data/local/tmp/tracer
adb push target/aarch64-linux-android/debug/examples/attach /data/local/tmp/subject
adb push /tmp/attach-tool /data/local/tmp/attach-tool
adb shell chmod 755 /data/local/tmp/tracer /data/local/tmp/subject /data/local/tmp/attach-tool
adb shell /data/local/tmp/tracer                                    # clean
adb shell /data/local/tmp/attach-tool /data/local/tmp/tracer        # traced from the start
adb push tests/platform/controls/trace-after-start.sh /data/local/tmp/
adb shell sh /data/local/tmp/trace-after-start.sh \
    /data/local/tmp/subject /data/local/tmp/attach-tool             # attached later

# The baseline and the unaccounted-code pairs, through LD_PRELOAD.
"$NDK_CC" -shared -fPIC -o /tmp/delayed.so tests/platform/controls/delayed.c
"$NDK_CC" -shared -fPIC -o /tmp/agent.so tests/platform/controls/agent.c
```

The Rust `attach` example and `attach.c` share a name, so the subject goes to the device as
`subject`. Two binaries under one name is a control that traces itself and reports nothing.

The runner needs `adb` on the path, and one device attached. The linker line is not optional:
Cargo links with `cc`, which is the host compiler here, and the Apple linker refuses the arguments
that Cargo passes. `run.sh` found this, because the recipe worked in a shell that already exported
the name and nowhere else.

## Gaps

Each line blocks something concrete. The order is the cost of closing it, cheapest first.

Two rows were the largest, and both were absent until 2026-08-13, because this list records what a
built thing lacks a control for and neither category was built. Both landed on 2026-08-19, and the
first three rows below are what is left of them.

| Gap | What it blocks |
|---|---|
| `dispatch` on three platforms | Nothing that blocks a detector, and it bounds what the category reaches. `instrumentation.dispatch_targets` answers on Linux and Windows since 2026-08-19, and macOS, iOS, and Android each read `plan`. Each cell needs its own measurement, and two are harder than they first look. **macOS uses classic lazy binding.** Measured on macOS 26 and ARM64 on 2026-08-19: a Rust build carries `LC_DYLD_INFO_ONLY`, not chained fixups, so its `__la_symbol_ptr` entries resolve on first call and move after start, which a naive read reports as a redirect. Only the non-lazy `__got` is bound at load, and on that build it holds three entries, one of which is `dyld_stub_binder`, so the safe table is tiny and awkward to redirect for a control. A macOS rule must read `__got` alone, or gate on chained fixups, and a hostile control needs a safe non-lazy import to redirect. iOS shares the Mach-O layout and the same question. **Android forks from zygote**, so the main image is `app_process64`, whose imports are shared across every app rather than the host's own, and the main-image rule may watch the wrong table there. Each waits for a probe that walks that platform's table and a measurement that models it, so a rule rests on what a real table holds rather than an assumption. |
| The platform half of `UiAbuse` | Nothing that a host needs, and it bounds what the category reaches. The detector landed on 2026-08-19 and it takes a host report, because two measurements showed that no operating system answers this question. **The overlay half is closed to a library.** On Android 37, `WindowManager` declares 41 methods and only the two screen-recording ones touch it, so nothing states that another application draws above this one; that evidence is `MotionEvent.FLAG_WINDOW_IS_OBSCURED`, which reaches a `View` the host owns. **The screen-recording half could move into the probe.** `addScreenRecordingCallback` registered from an application context and the SDK source anchors it to any activity of the registering uid, so a probe could read it where the host declares `DETECT_SCREEN_RECORDING` and the system is API 35 or later. That would save the host one call and change no finding. **One thing stayed unverified.** With an activity of that uid resumed and `adb shell screenrecord` running for 10 s, the callback never fired and the state stayed 0. Whether the shell recorder bypasses the bookkeeping that drives it needs a second application that starts a `MediaProjection`, and this project built none. Reaching the context at all takes a call on a list that Google owns and revises per release, which no compile reports, and that is the standing argument against moving any of this into the probe. |
| The clean half of `Virtualization`, on three platforms | Nothing that blocks a detector, and it bounds what the record proves. `emulation` answers on macOS, Linux, Windows, and Android since 2026-08-19, and iOS is the one cell that still reads `plan`. Linux, Windows, and Android hold the hostile arm alone: every Linux, Windows, and Android control of this project runs in a guest or an emulator, so no run of this harness has ever seen one of those three report the hardware. The rule that decides the clean answer is covered by unit tests and by a captured firmware table, and only the live half is open. macOS holds both arms, because this development machine is the bare metal. iOS holds neither, and the row below it states why.
| The machine host on iOS | One cell of one v1 category, and the last one. Measured on 2026-08-19 in an iOS 18.5 simulator: a process reads the kernel of the Mac that hosts it, so `kern.hv_vmm_present`, `hw.machine`, and `hw.model` each report what the Mac reports and none of them describes the simulator. So the macOS reader cannot be shared, and any rule that separated a simulator from a device would rest on a device value that this project has never read. A device closes this, and it is the same device that two rows below ask for.
| A full scan after a mobile resume | The lifecycle promise in [runtime and API](../../docs/plan/03-runtime-and-api.md#lifecycle). The plan makes a full scan the worker's first work item after the operating system resumes the application, and neither mobile probe does that yet. Both `lifecycle.rs` files state it, and nothing outside the source did until 2026-08-18. iOS needs an application lifecycle notification, and Android needs the Java callback that owns the same event, so each one arrives with an application harness that produces the event. A desktop worker runs continuously, so this reaches iOS and Android only. |
| An Android device | The row above, and any measurement that an emulator cannot make. Every Android result in this record came from an emulator, and that now includes the rooted one. A vendor build of a real handset may write something else in `ro.build.tags`, and no emulator answers that. |
| An iOS device, for an image that names its team | The positive half of iOS `identity`. The reason is now measured rather than assumed. On 2026-08-18 a team entitlement was refused in four combinations on the iOS 26 simulator: a bare binary and an installed app bundle, each with an ad-hoc signature and with a real Apple Development certificate from a team that holds a valid provisioning profile. The same bundle with no entitlement launches, so the binary and the bundle are not the cause. A simulator has no provisioning mechanism at all, so no signature can grant an entitlement there, and only a device can. Every iOS control therefore ran against an image that names no team, and the probe has never read a real one. The reader is proven against a recorded signature that does carry one, and the comparison is a plain function that the tests cover, so only the join of the two is open. |
| A system application on Android | Nothing that a host needs. Android installs a system application outside `/data/app/`, under a name of its own, so the exact rule that selects an archive reports a gap for one. A host application always installs under `/data/app/`. |
| The 4 controls that a person still drives | Nothing that blocks a release, and it bounds what the generated record proves. `run.sh` now drives every control that can state its own answer. The 4 that remain state none: `phases.m` needs a window server and a run loop, `qos-drift.c` measured one design choice that is already made, `entitle.c` prints the entitlements of whatever image it runs in, which is a reading rather than a result, and `machine-paravirtual-linux` needs a second monitor that the guest set does not hold. |
| A jailbroken iOS system | iOS `device`. The mechanism is reachable, because a jailbreak weakens the same kernel guarantees that the identity probe already reads. No control produces one, so no measurement exists and no code was written. |
| An iOS device | The iOS rows above. A simulator process runs on the macOS kernel, so it proves the mechanism and not the device. |
| An x86_64 machine of this project's own | The bare-metal half of the architecture claim. The gate runs the whole harness on `ubuntu-latest` and `windows-latest`, which are x86_64, and on `ubuntu-24.04-arm` and `windows-11-arm`, so every supported architecture of Linux and of Windows answers on every push. A hosted runner is still a virtual machine, so what stays open is bare metal, not the architecture. Android has no x86_64 detector result, because the emulator here runs ARM64. macOS needs none, because it runs on ARM64 alone. Until 2026-08-18 the cross-check held one x86_64 target, so the others could have broken unnoticed, and until that same day no CI run kept a single row of what it measured. |
| A false-positive survey, across profilers, crash reporters, and enterprise agents | Host guidance only, and no longer release tests. `debugging.tracer_present` carries a user-mode bypass, which the signal model puts at `Medium` on its own, so no survey lifts it. See [detectors and platforms](../../docs/plan/04-detectors-and-platforms.md#tracer-state). |
| A physical Windows host | What the Windows rows prove about a real machine, and the spread in the Windows cost column. Every Windows result came from the QEMU guest that `tests/platform/vm/windows/` builds. The detector answers should hold, because each one reads a documented kernel or `wintrust` interface rather than a timing. The cost figures do move: two runs on the same guest gave 296 us and 416 us for one `code_identity`, and the table holds the quieter run. See [state and budgets](../../docs/plan/07-state-and-budgets.md#measured-cost). |
| An anchor that Microsoft signed, on Windows | Nothing that blocks a release, and it bounds what the Windows identity rows prove. `controls/sign-windows.ps1` anchors a certificate that the guest itself made, so the rows prove that the tier reads a signature and compares a signer. They do not prove what the anchor set of a stock Windows accepts. |
