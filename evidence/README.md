# Verification evidence

This directory holds the record that [verification](../docs/plan/05-verification.md) requires, and
the controls that produce it. No size rule applies here, and nobody compresses a test record.

A cell reads `yes` only after a real run on a real system. A mock, a stub, and a successful
compilation are not evidence. A gap in this record is what blocks a platform from the supported
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
`crates/fidelity/tests/evidence.rs` bind them: a capability cannot report `yes` in the
[coverage matrix](../docs/plan/06-delivery.md#capability-coverage) while this record stays silent
about it, and the harness must name every control that exists.

## Detector coverage

Every finding below reports at the strength that
[detectors and platforms](../docs/plan/04-detectors-and-platforms.md) states. Every run used ARM64.
The capability and system names match the coverage matrix exactly, because the test compares them.

| Capability | Detector | System | Measured on | Clean control | Hostile control, and the result |
|---|---|---|---|---|---|
| `identity` | `integrity.platform_trust` | macOS | macOS 26 | a distributed image | a repackaged image, which it rejects, `Medium` |
| `identity` | `integrity.expected_identity` | macOS | macOS 26 | a distributed image, a local build, and a second certificate of the same team, which all stay clean | a repackaged image, and a pin to another signer, which both report, `High` |
| `identity` | `integrity.platform_trust` | iOS | iOS 26, simulator | the tier reports `Unsupported`, because the iOS SDK ships no `SecCode.h`, checked 2026-08-10 | none. An `Unsupported` tier creates no finding, so it has no hostile control. |
| `identity` | `integrity.expected_identity` | iOS | iOS 26, simulator | a local build names no team, and an absent or accepted host value reports `Unsupported` | a pinned team, against an image that names none, which reports, `High` |
| `identity` | `integrity.platform_trust` | Android | Android 37, emulator | the tier reports `Unsupported`, because Android accepts any self-signed certificate and anchors none | none. An `Unsupported` tier creates no finding, so it has no hostile control. |
| `identity` | `integrity.expected_identity` | Android | Android 37, emulator | an instrumented test reads the certificate of its own archive, and it equals what `PackageManager` reports for the same package | a pinned digest against another certificate, which reports, `High` |
| `baseline` | `integrity.runtime_baseline` | macOS | macOS 26 | two JavaScript hot loops, which add no region, and 40 s with no finding | an agent maps 64 KiB after start, caught after 5.6 s to 7.1 s, `Medium` |
| `baseline` | `integrity.runtime_baseline` | iOS | iOS 26, simulator | 40 s with no finding | an agent maps 64 KiB after start, caught after 5.9 s, `Medium` |
| `baseline` | `integrity.runtime_baseline` | Linux | Debian, glibc | 40 s with no finding | an `LD_PRELOAD` agent maps 64 KiB after start, caught after 6.1 s to 6.8 s, `Medium` |
| `baseline` | `integrity.runtime_baseline` | Android | Android 37 | a system application maps 410 regions | an agent maps executable memory after start, caught, `Medium` |
| `tracer` | `debugging.tracer_present` | macOS | macOS 26 | a run with no debugger | `lldb`, at start and attached later, both report, `Medium`, and the later one is caught after 5.4 s to 5.8 s |
| `tracer` | `debugging.tracer_present` | iOS | iOS 26, simulator | a run with no debugger | `lldb` attached after start, caught after 5.9 s, `Medium`, and the operation denied |
| `tracer` | `debugging.tracer_present` | Linux | Debian, glibc | a run with no debugger | `gdb`, and `attach.c` in both of its forms, all report, `Medium`, and the later one is caught after 5.3 s to 5.8 s |
| `tracer` | `debugging.tracer_present` | Android | Android 37 | a run with no tracer | a `ptrace` tracer on a device, reports, `Medium` |
| `injection` | `instrumentation.unaccounted_code` | Linux | Debian, glibc | a plain process holds no anonymous executable region | an `LD_PRELOAD` agent maps 4 KiB, reports, `Medium` |
| `injection` | `instrumentation.unaccounted_code` | Android | Android 37 | a real runtime names its code caches `[anon_shmem:dalvik-jit-code-cache]` | an agent maps executable memory, reports, `Medium` |
| `device` | `device_compromise.system_build` | Android | Android 36 and 37, emulators | a Play Store system image, which reports `release-keys` and `ro.debuggable=0`, and stays clean | a Google APIs system image, which reports `dev-keys` and `ro.debuggable=1`, and reports, `Medium` |
| `lifecycle` | none | macOS | macOS 26 | a prepared worker thread reports the utility class, and an untouched thread does not | none. The capability reports no finding, so it has no hostile control. |
| `lifecycle` | none | iOS | iOS 26, simulator | the same two controls, in the simulator | none. The capability reports no finding, so it has no hostile control. |
| `lifecycle` | none | Android | Android 37, emulator | an instrumented test attaches a thread the machine has never seen, both from a host handle and by discovery, and a shell binary that runs no machine reports that gap | none. The capability reports no finding, so it has no hostile control. |

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
[detectors and platforms](../docs/plan/04-detectors-and-platforms.md):

- `High` is **closed** on `integrity.runtime_baseline` and on `instrumentation.unaccounted_code`,
  rather than pending. A benign explanation that is common cannot support `High`, and loading a
  plugin is common. The finding carries the evidence that the hostile control produces, so nothing
  separates the two.
- A host that embeds a web view creates the view before it calls `start()`. The cost lands once, at
  creation, and no later navigation reports.

Three negative results carry the same weight as the rows above, and
[detectors and platforms](../docs/plan/04-detectors-and-platforms.md) records each one in its
excluded-mechanisms table: the macOS hardened runtime refuses `DYLD_INSERT_LIBRARIES`, a later
`dlopen` leaves the dyld image list in order, and no absolute count of unattributed executable
memory works on Apple, because a clean process holds about 3.6 GB of it across 13 to 16 regions.

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
[ADR-0007](../docs/adr/0007-value-producing-check.md) records both. Both key inputs ship inside the
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

[State and budgets](../docs/plan/07-state-and-budgets.md) holds the numbers and the ceiling. Every
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

[Verification](../docs/plan/05-verification.md) requires two results from this pair of controls, and
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

## The generated record

`run.sh` ran the whole set on 2026-08-11, on macOS 26 and ARM64, with a booted iOS simulator, a
running Docker daemon, and an Android 37 emulator attached. It ran 48 controls, every one of which
passed. It skipped one, Miri, which `05-verification.md` schedules rather than running every time,
and it wrote 3 `manual` rows. The whole run takes about 6 minutes, and three clean controls spend
40 seconds each waiting for a finding that must never arrive.

Eighteen of the 48 are the hostile controls and their clean halves, which used to need a person.
Each `caught after` figure is the time a host is exposed for, and it is the number that matters
most. Each one below holds two runs, because the worker interval carries jitter and a single figure
would read as a constant:

| Control | System | Answer |
|---|---|---|
| `baseline-hostile` | macOS | `delayed.c` maps 64 KiB after start, caught after 5.6 s and 7.1 s |
| `baseline-clean` | macOS | 40 s with no finding |
| `tracer-at-start` | macOS | `lldb -b` runs the whole program, found by the initial scan |
| `tracer-attaches` | macOS | `lldb -p` attaches after start, caught after 5.4 s and 5.8 s |
| `tracer-clean` | macOS | a run with no debugger |
| `baseline-hostile-linux` | Linux | the same agent, caught after 6.1 s and 6.8 s |
| `baseline-clean-linux` | Linux | 40 s with no finding |
| `inject-hostile` | Linux | `agent.c` maps 4 KiB, reported, and the operation denied |
| `inject-clean` | Linux | a loader that maps a library from a file reports nothing |
| `tracer-at-start-linux` | Linux | `attach.c` traces from exec, found by the initial scan |
| `tracer-attaches-linux` | Linux | `attach.c` attaches after start, caught after 5.3 s and 5.8 s |
| `tracer-clean-linux` | Linux | a run with no tracer |
| `plugin-load` | macOS | 1 region before, `+0` for a cached library, `+1` for a plugin |
| `plugin-load-linux` | Linux | 4 mappings before, `+1` for `libm`, `+1` for a plugin |
| `legitimate-plugin` / `-linux` | macOS, Linux | a host loads its own plugin after start, reported after 7.1 s and 5.6 s |
| `legitimate-cached` | macOS | a host loads a cached library after start, 40 s with no finding |
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

**A control that nobody compiles stops compiling.** `attach.c` held its build command in its own
header comment, and that command named an NDK directory with a star and a slash in it. Those two
characters close a C comment, so the file had not compiled since the line landed. The comment now
carries the rule that a path in a comment holds no glob, and the harness compiles the file on every
run.

**A version that nothing builds is a claim, not a pin.** `Cargo.toml` names 1.85 as the minimum
Rust version, and [delivery](../docs/plan/06-delivery.md) makes that normative. Measured on
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
| `controls/attach.c` | a tracer finding where no debugger is available. It is a minimal `ptrace` tracer, in two forms: it traces a program from its own exec, or it attaches to a process that already runs. |
| `controls/trace-after-start.sh` | the tracer control that only the worker can catch. It starts the `attach` example, reads the process identifier that the example prints, and puts a tracer on it. `lldb -p` is the tracer on macOS, and `attach.c` is the tracer on Linux and on Android. |
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

```sh
evidence/run.sh
```

It writes `record.tsv`, and it leaves the output of each control under `target/evidence/`. Each
section below sets up one system that the harness reports as skipped, so boot a simulator, start
the container daemon, or attach a device, and run it again. The Linux row keeps its own build
directory in a Docker volume named `fidelity-evidence-target`, because the host and the container
otherwise fight over one `target/`.

### iOS, on the simulator

```sh
xcrun simctl boot "iPhone 16 Pro"
export FIDELITY_IOS_SIM=$(xcrun simctl list devices | awk '/Booted/ {print $(NF-1)}' | tr -d '()')
export CARGO_TARGET_AARCH64_APPLE_IOS_SIM_RUNNER=$PWD/evidence/controls/run-ios.sh
cargo test -p fidelity-probe-apple --target aarch64-apple-ios-sim

# The hostile control for the baseline.
SDK=$(xcrun --sdk iphonesimulator --show-sdk-path)
clang -arch arm64 -isysroot "$SDK" -mios-simulator-version-min=18.0 \
    -dynamiclib -o /tmp/delayed.dylib evidence/controls/delayed.c
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
cargo run --release --example cost -p fidelity-probe-linux            # inside the container
cargo run --release --example cost -p fidelity-probe-android --target aarch64-linux-android
```

The Android line measures a shell binary, which maps no archive. `./gradlew
connectedDebugAndroidTest` measures an application process, and it prints both numbers to logcat
under the `fidelity` tag.

### Linux, in a container

```sh
docker run --rm -it --cap-add=SYS_PTRACE -v "$PWD:/work" -v "$PWD/evidence/controls:/src" \
    -e FIDELITY_BUILD_SEED=test -e FIDELITY_CODE_IDENTITY=none -e CARGO_TARGET_DIR=/tmp/target \
    rust:slim sh
```

`CARGO_TARGET_DIR` matters: without it the container and the host fight over one `target/`.

### Android, the instrumented harness

Two Android test paths exist, and they answer different questions. The runner below runs the Rust
unit tests on the device, which covers everything the kernel answers. It cannot reach a Java
interface, because a shell binary has no JVM and no package. The instrumented harness in
`crates/probe/fidelity-probe-android/android/` supplies both, because it runs inside an application
process.

```sh
$ANDROID_HOME/emulator/emulator -avd Pixel_10_Pro_XL -no-window -no-audio -no-snapshot &
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

### Android, on a device or an emulator

```sh
NDK_CC=$(ls "$ANDROID_HOME"/ndk/*/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android*-clang | tail -1)
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$NDK_CC
export CARGO_TARGET_AARCH64_LINUX_ANDROID_RUNNER=$PWD/evidence/controls/run-android.sh
cargo test -p fidelity-probe-android --target aarch64-linux-android
```

The runner needs `adb` on the path, and one device attached. The linker line is not optional:
Cargo links with `cc`, which is the host compiler here, and the Apple linker refuses the arguments
that Cargo passes. `run.sh` found this, because the recipe worked in a shell that already exported
the name and nowhere else.

## Gaps

Each line blocks something concrete. The order is the cost of closing it, cheapest first.

The first two rows are the largest, and they were absent from this list until 2026-08-13. This list
records what a built thing lacks evidence for, and neither of those two is built, so nothing here
noticed them. Read them first.

| Gap | What it blocks |
|---|---|
| A `UiAbuse` detector | Half of one v1 category. `interface` reads `plan` on iOS and Android, no capability trait exists, and [detectors and platforms](../docs/plan/04-detectors-and-platforms.md) specifies no detector for it. The technical unknown is closed: measured on 2026-08-13 on two Android images, a library reaches an application `Context` by itself, and the window service and package manager both answer through it. See the [platform notes](../docs/research/platform-notes.md). **The recommendation is to leave the cell at `plan`, and the greylist is the smaller reason.** What that `Context` reaches is lists of other applications: which ones hold `SYSTEM_ALERT_WINDOW`, and which accessibility services are enabled. This project already treats a package list as supporting evidence only, and an enabled accessibility service is far more often a person who needs one than an attacker. The evidence that separates the two, an obscured touch or a screen-capture callback, arrives on the host's own window, so the host reads it and Fidelity cannot. That last reading is unverified, and it is the first thing to measure if this reopens. |
| A `Virtualization` detector | One whole v1 category. `emulation` reads `plan` on all five platforms, no capability trait exists, and no detector is specified. Unlike `UiAbuse` this one is control-blocked as well: the clean and hostile pair needs a physical Android device, or macOS in a virtual machine, or bare-metal Linux, and this machine supplies none of the three. |
| An Android device | The row above, the rooted-system row, and any measurement that an emulator cannot make. Every Android result in this record came from an emulator. |
| An image that names its team, on iOS | The positive half of iOS `identity`. Apple restricts a team entitlement to a provisioned build: an ad-hoc signature that carries one is refused at launch, measured on macOS 26 and on the iOS 26 simulator on 2026-08-10, both with `SIGKILL`. Every iOS control therefore ran against an image that names no team, so the probe has never read a real one. The reader is proven against a recorded signature that does carry one, and the comparison is a plain function that the tests cover, so only the join of the two is open. |
| A system application on Android | Nothing that a host needs. Android installs a system application outside `/data/app/`, under a name of its own, so the exact rule that selects an archive reports a gap for one. A host application always installs under `/data/app/`. |
| The 3 controls that a person still drives | Nothing that blocks a release, and it bounds what the generated record proves. `run.sh` now drives every control that can state its own answer. The 3 that remain state none: `phases.m` needs a window server and a run loop, `qos-drift.c` measured one design choice that is already made, and `entitle.c` prints the entitlements of whatever image it runs in, which is a reading rather than a result. |
| A jailbroken iOS system | iOS `device`. The mechanism is reachable, because a jailbreak weakens the same kernel guarantees that the identity probe already reads. No control produces one, so no measurement exists and no code was written. |
| A rooted Android system | Nothing that blocks a release, and it would measure the coverage limit. `device_compromise.system_build` reads what the system says about itself, and a root tool rewrites that. A Magisk install would show how much a released-build answer is worth. |
| An iOS device | The iOS rows above. A simulator process runs on the macOS kernel, so it proves the mechanism and not the device. |
| A false-positive survey, across profilers, crash reporters, and enterprise agents | Host guidance only, and no longer release evidence. `debugging.tracer_present` carries a user-mode bypass, which the signal model puts at `Medium` on its own, so no survey lifts it. See [detectors and platforms](../docs/plan/04-detectors-and-platforms.md#tracer-state). |
| Windows | Every Windows row. The platform needs a real machine or a cloud runner. |
