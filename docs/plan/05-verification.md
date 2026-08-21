# Verification

## Ownership

Fidelity owns detector correctness, action semantics, bounded state, and consistency across its
supported targets. The consuming application owns the final MASVS and MASTG assessment of its
packaged mobile application. The [security model](02-security-model.md) assigns the rest.

`fidelity-testkit` is internal and makes no promise to a consumer. A host therefore proves its
`ensure_allowed()` placement against a real hostile environment, not against an injected latch.

The test record is generated and machine-readable, and it lives with the tests. No size rule
applies to it, and nobody compresses it. For each detector and platform pair, Fidelity records:

- a clean control and its false-positive observations;
- a representative hostile control;
- the expected finding, strength, evidence, and configured action;
- the supported OS and architecture range; and
- known bypasses, and the conditions that force `Unsupported` or a health finding.

A mock that produces the output of a detector does not implement that detector. At least one
representative real hostile test must exercise the backend mechanism.

## Parser attack tests

The independent `fuzz/` workspace attacks these 14 input families:

- APK ZIP;
- APK signature;
- Mach-O signature;
- Mach-O entitlements;
- Mach-O dispatch;
- Mach-O image commands;
- ELF dynamic arrays;
- ELF relocations;
- PE imports;
- PE certificate boundaries;
- SMBIOS;
- proc maps;
- bounded text; and
- identity inputs.

A pull request runs 256 seeded cases for each target. The daily schedule runs each target for 30
minutes. A release candidate runs each target for two hours.

The workflows pin nightly-2026-06-14. The fuzz workflow pins cargo-fuzz 0.13.2. The fuzz lock file
pins the target dependencies.

Each target accepts arbitrary bytes or valid UTF-8 text. A malformed value must return a bounded
answer and must not panic. Linux and Android give bounded ELF slices to the safe readers. Apple
checks its mapped ranges before it gives bounded command slices to the safe readers. Windows copies
readable image pages into a bounded buffer before the PE reader runs.

## Test layers

| Layer | Purpose | Required timing |
|---|---|---|
| Unit | strength ordering, category sets, latches, retention, callback rules, evidence truncation | every change |
| Unsafe wrappers | the address and thread sanitizers over the whole workspace, and Miri over the crates that forbid unsafe code | sanitizers every change, Miri scheduled |
| Engine integration | initial-scan ordering, worker lifecycle, isolated test runtimes | every change |
| Platform clean | supported clean configurations, enterprise and security-tool compatibility, API failure paths | pull request where deterministic, otherwise scheduled |
| Platform hostile | debugger, injection, hooking, root, jailbreak, tamper, emulator, and VM controls as applicable | release tests; deterministic cases on pull requests |
| Consumer | packaged app behavior, protected operation placement, MASTG tests | consuming application |

A test that stops the process runs in a child process. Callback tests prove that the runtime latches
the state before it invokes the callback, that a panic in the callback leaves the worker alive, and
that `ensure_allowed()` and `snapshot()` both return when the callback calls them. Denial tests
prove that categories accumulate and never clear, that a host latch stays distinguishable from a
detector latch, and that `ensure_allowed()` and `snapshot()` never disagree about the latch. State
tests prove that a slot reads `NotRun` until a scan reaches it, and never reads clean before then.
Retention tests prove that repeated findings never grow the state.

Worker tests prove that a change after start reaches the detector state and the category latch on a
later cycle, and that the finding stays after the change reverses. The initial scan cannot show any
of that, because it runs once. A test states one answer for each scan, so the environment changes
under the worker the way a real one does.

Guarded-constant tests prove that a correct identity returns the literal, that a wrong identity
returns a wrong value rather than an error, that two builds of the same source produce different
ciphertext, and that no heuristic detector changes the result. A failed identity read must never
return the literal. Two constants in one build must expand to different code, and a rotated seed
must change the binary, because a stale seed keeps the old key without any error. A wrong key must
give a well-formed value across a large sample of keys, because one decode failure is an oracle.

A build that binds to a code identity must fail its start where the running image reports none. A
guarded read has no error path, so every read would otherwise return a wrong value and report
nothing. The test covers an unsigned image, an image signed ad hoc, a platform without the
capability, and a failed read.

Release tests add an extraction test, and they record a limit rather than a defense. Both key
inputs ship inside the artifact, as [ADR-0007](../adr/0007-value-producing-check.md) states, so one
extractor that knows the derivation reads every guarded constant, in every build, offline. The test
records that ceiling. It then proves the property that the design does promise: an image that
another signer repackaged returns wrong values where the original returns right ones.

Policy tests prove that `Crash` never fires on a detector-health finding, and that every other
action still does. Identity cross-check tests prove that a patched identity source disagrees with
the remaining sources, and that the disagreement is an `Integrity` finding.

The tracer detector needs three controls on each platform: a clean run, a run that starts under a
debugger, and a debugger that attaches after start. The third is the realistic attack, and only the
worker can catch it. Record the time it took, because that time is what a host is exposed for.

Image identity needs five controls where the host pins a signer: a distributed image, a locally
built image, a repackaged image, an image that a second certificate of the same signer signed, and
a distributed image against an identity that the host pinned to another signer. The fourth must stay
clean and the fifth must report, because that pair proves that the two tiers answer different
questions. Windows, macOS, iOS, and Android pin a signer.

A platform that pins content rather than a signer needs four, and the fourth arm has no meaning
there. Linux pins a content digest, so a second certificate of one signer names nothing, and the
remaining four are the clean pin, the repackaged image, the pin to another value, and the state of
the platform trust tier. A control that a platform cannot express is a gap that the record states,
and never a control that a release counts as absent.

Architecture tests keep the workspace in the shape that [delivery](06-delivery.md) states. They
prove that a probe crate imports no detector and no engine, that `unsafe` stays inside a `sys`
module, that no crate takes a remote-network dependency, that no probe declares a feature, and that
only the platform seam carries a target condition. Each rule must fail when a change breaks it, so
each one is checked against a deliberate violation before it lands.

A surface test holds the public items of the `fidelity` crate and of the types it re-exports, as a
snapshot that the repository carries. The gate fails when the code and the snapshot disagree, so an
addition updates the snapshot in the same change, and a removal or a rename states itself in the
changelog. The snapshot reads Rust as text, so it holds a declaration and not a resolved type, and
it reads no `cfg`. One macro writes six public methods, so a second rule proves that its body still
generates the signature that the snapshot expands.

The Tauri adapter has a second, smaller surface rule. It locks `init`, `FidelityExt`, and its two
methods. The same rule rejects an invoke handler or a WebView command. A mock-runtime test executes
the setup hook and reads the stored `Handle` from Tauri state.

`tests/package.sh` locks the files in the two public archives. It checks every facade feature
combination and builds the packaged workspace with Rust 1.85. It makes two independent production
archive sets and compares each pair byte for byte. It also checks the Tauri adapter with Rust 1.88
and its locked Tauri 2 dependency set.

Capability tests keep the [coverage matrix](06-delivery.md#capability-coverage) true. A trait that
defaults to `Unsupported` lets a gap stay silent, so the table states the intent and a test compares
it against the code. The rules prove that:

- every capability trait holds a row, and every probe crate holds a column;
- a `yes` cell has platform code behind it, and a `plan` cell or a `no` cell has none;
- the platform seam constructs every probe that a `yes` cell names; and
- a detector reads every capability that reports a finding.

Miri cannot cross a foreign call, so it never reaches a probe crate, and the sanitizers are what
cover the `unsafe` there. Run both with `tests/platform/controls/run-sanitizers.sh`. Exclude a
doc-test: rustdoc links one without the sanitizer runtime, so every doc-test fails to link and none
of those failures describes this workspace.

`test_record.rs` binds the record in `tests/platform/` to the same matrix, in the other
direction. A `yes` cell claims that a platform answers, and only a real clean control and a real
hostile control make that claim legitimate, so the record holds a row for every `yes` cell. The
rules also prove that a row names a detector that exists, a system that the matrix holds, and a
control file that is present. They do not prove that a row is true. One row names no capability and
no system, because `UiAbuse` reads no operating system, and the rules exempt exactly that row and
fail if a second one appears. `tests/platform/run.sh` runs every control that a machine
can reach and generates the record, and one rule proves that the harness names every control that
exists. A control that no machine here can reach gets a row that says so, because a record of what
passed alone reads as complete coverage. A person still judges what a hostile control produced.

## Mobile test provenance

The mobile harness uses current MASTG test cases as reproducible hostile-test input. This covers
root, jailbreak, debugger, reverse-engineering tool, and runtime-hook scenarios that match a
Fidelity detector.

The verification metadata pins the mapping to a MASTG version. Review it when OWASP changes an
identifier or the test content. A deprecated MASTG test can inform a migration. It is not a
current release test.

## Release tests

A release candidate must show:

- the workspace, examples, rustdoc, formatting, lints, and deterministic tests pass;
- every supported platform and architecture builds with its intended toolchain;
- a real clean control and a real hostile control exist for each enabled detector;
- measured overhead per platform meets the
  [performance budget](07-state-and-budgets.md#performance-budget);
- Fidelity reports an unsupported capability accurately, and never stubs it as a success;
- the team revalidated the OS floors, the standards identifiers, and every undocumented-interface
  assumption;
- the team checked finding and snapshot schema compatibility, and the retention bounds;
- each dependency graph has no RustSec vulnerability and uses an accepted source; and
- the change introduced no remote network path, and no accidental Tauri command surface.

Rooted devices, jailbroken devices, and physical mobile hardware may run in a controlled release lab
instead of on every pull request. A missing release test still blocks the platform from the
implemented label.

## Standards traceability

Verified against OWASP MASVS 2.1.0 and MASTG 2.0.0 on 2026-08-21. Every identifier, weakness title,
and MASVS category below comes from the live site. OWASP publishes the category, not the numbered
control, so the MASVS control column is this project's own reading and is unverified.

| Fidelity category | OWASP MASWE weakness | MASVS control |
|---|---|---|
| `DeviceCompromise` | [MASWE-0051](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0051/) root/jailbreak detection not implemented | [RESILIENCE-1](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-1/), [RESILIENCE-4](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-4/) |
| `Virtualization` | [MASWE-0052](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0052/) app virtualization environment detection not implemented | RESILIENCE-1 |
| `Virtualization` | [MASWE-0053](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0053/) emulated or virtual device detection not implemented | RESILIENCE-1, RESILIENCE-4 |
| `Integrity` | [MASWE-0058](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0058/) runtime code integrity not verified | [RESILIENCE-2](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-2/) |
| `Debugging` | [MASWE-0064](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0064/) debugger detection not implemented | RESILIENCE-4 |
| `Instrumentation` | [MASWE-0065](https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0065/) dynamic analysis tools detection not implemented | RESILIENCE-4 |
| `UiAbuse` | [MASWE-0039](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0039/) app vulnerable to overlay attacks | [PLATFORM-3](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-3/) |
| `UiAbuse` | [MASWE-0040](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0040/) sensitive data leaked via accessibility services | PLATFORM-3 |
| `UiAbuse` | [MASWE-0038](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0038/) insufficient protection of sensitive data from screenshots or screen recordings | PLATFORM-3 |

`UiAbuse` is the only category outside MASVS-RESILIENCE. Part of each of those three mitigations is
preventive: the host sets `FLAG_SECURE`, or it filters obscured touches. Fidelity supplies the
detection half. Setting a flag on the host's own windows is the host's job.

Not v1: MASWE-0054 device attestation, MASWE-0056 app attestation, MASWE-0057 app resources
integrity, and the obfuscation weaknesses MASWE-0059 and MASWE-0060 under
[MASVS-RESILIENCE-3](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-3/).

MITRE D3FEND applies only where a detector implements the exact defensive technique, for example
[Process Code Segment Verification (D3-PCSV)](https://d3fend.mitre.org/technique/d3f%3AProcessCodeSegmentVerification/)
or [Process Self-Modification Detection (D3-PSMD)](https://d3fend.mitre.org/technique/d3f%3AProcessSelf-ModificationDetection/).
MITRE ATT&CK names attacker behavior, not Fidelity controls:
[process injection (T1055)](https://attack.mitre.org/techniques/T1055/) on desktop,
[process injection (T1631)](https://attack.mitre.org/techniques/T1631/) and
[hooking (T1617)](https://attack.mitre.org/techniques/T1617/) on mobile, and
[disguise root/jailbreak indicators (T1630.003)](https://attack.mitre.org/techniques/T1630/003/).
Reversed mappings, such as attacker anti-debugging or virtualization evasion, are omitted. This
project keeps no CWE column, no CAPEC column, and no coverage count.
