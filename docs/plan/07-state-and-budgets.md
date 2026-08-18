# State and budgets

What the runtime keeps, and what it is allowed to cost. The [runtime and API](03-runtime-and-api.md)
covers what the host calls.

## Findings and snapshots

A snapshot separates the categories that a detector latched from the categories that the host
latched with `Handle::deny()`. A host latch carries no finding, so without the separation a reader
cannot explain the denial.

A finding carries the detector, the category, the `SignalStrength`, typed evidence, and
`observed_at_unix_ms`. `Detector` is an opaque handle with a stable `name()` and a `category()`.
The detector inventory is not a public enumeration, so a new detector is not a breaking change. A
host routes on the category and logs the name. The wall-clock timestamp is informational and may
move backwards. There is no finding envelope, no sequence number, and no runtime identifier:
nothing streams, so nothing needs ordering.

`snapshot()` returns the authoritative state. Fidelity does not persist it and does not serialize it
for the host. An optional `serde` feature, off by default, provides `Serialize` for the public
types, so a host that exports a finding chooses its own format. Fidelity owns the field names and
their meaning. New fields are additive, and a field never changes meaning after release.

## Memory budget

Long-running memory use must not depend on finding frequency or attacker-chosen identifiers.
Fidelity stores no event ring and no chronology. It keeps one state slot per built-in detector, and
an observation cannot create a slot. Each slot starts at `NotRun` and retains the current outcome,
the strongest-ever finding and evidence, the first and latest finding timestamps, and a saturating
occurrence count.
The host owns any durable history. Evidence is bounded to 4 KiB per retained outcome, with
truncation metadata when a safe text field exceeds its limit.

Tests must prove that repeated findings and recoveries never increase retained state.

## Guarded constant budget

`guarded!()` expands inline for each constant, so it trades size and time for the removal of a
shared reader. See [ADR-0007](../adr/0007-value-producing-check.md).

- About 1 KiB of code for each guarded constant. The cost is linear in the number of constants, so
  a host that wraps 20 constants pays about 20 KiB.
- About 700 ns for each read of a 16-byte constant, measured on macOS 26 and ARM64. Half is the key
  derivation and half is the stream, and both grow with the length: about 1.5 us at 64 bytes. There
  is no cache, so a host that reads inside a hot loop hoists the read out of the loop.
- The code identity is read once, at start. The first read costs between 4 ms and 8 ms on macOS,
  which no read path can spend. An attacker therefore has to win that race once rather than on
  every read. The worker still re-reads the identity on every cycle as a detector, so a later
  change is reported.
- A `Secret<N>` holds its plaintext on the stack and wipes it on drop. The wipe is best effort: a
  compiler may keep a copy that the wipe does not reach.

The first vertical slice records the measured size and time per constant, and that measurement
becomes the ceiling in the same way the performance budget below does.

## Runtime baseline budget

The baseline holds the executable regions that `start()` captured, and it holds 1024 at most, which
is about 16 KiB. Measured on Android 37, a system application maps 410 executable regions, so the
limit leaves room and still bounds the cost. A process that passes the limit gets `Unsupported`
rather than a partial baseline that reads as complete.

The cost does not grow with time, with finding frequency, or with anything an attacker chooses. A
later scan allocates one snapshot, compares it, and drops it.

A probe reads the top-level regions only, and it does not descend into a submap. Measured on macOS
26 and ARM64, the descending walk costs 27 ms and the top-level walk costs 36 us, because the dyld
shared cache is a submap of about 1.7 GB. Both see an injected mapping arrive, so the cheap walk
loses no evidence. A scan that spent 27 ms every cycle would leave the steady-state budget below.

## Performance budget

Fidelity runs inside someone else's process, so its cost is a product constraint, not an
implementation detail.

- `ensure_allowed()` is a read of latched state. It must not scan, allocate, or block.
- `start()` must not stall the host. If the initial scan cannot finish inside its bound, the backend
  reports a `Low` detector-health finding and starts anyway.
- Steady-state worker cost must stay negligible against an idle host process.
- A mobile worker must never prevent the OS from suspending the application.

The first vertical slice measures baseline overhead on each platform. That measurement becomes the
recorded ceiling, and it is [the platform test record](05-verification.md). A later release that
exceeds its recorded ceiling fails the release gate.

### Measured cost

`cargo run --release --example cost`, in the probe crate of the platform, prints every number
below. `crates/probe/measure.rs` holds the loop that all four examples share, so the numbers
compare directly. Each read goes through `&dyn Environment`, which is the call the engine makes,
and which is also the only form the optimizer cannot lift out of the loop. Every column used ARM64.
The first four were measured on 2026-08-10, and the Windows column on 2026-08-18 in the QEMU guest
that `tests/platform/vm/windows/` builds:

| Read | macOS 26 | iOS 26, simulator | Debian, glibc | Android 37 | Windows 11 |
|---|---|---|---|---|---|
| `code_identity` | 190 us | 84 ns | none | 52 us | 296 us |
| `identity_match` | 150 us | 102 ns | none | 51 us | 98 us |
| `tracer_state` | 18 us | 20 us | 3.6 us | 4.8 us | 1.2 us |
| `code_regions` | 58 us | 70 us | 9.7 us | 35 us | 411 us |
| `code_origin` | none | none | 9.3 us | 35 us | 410 us |
| one worker cycle | 416 us | 90 us | 23 us | 178 us | 1.2 ms |

Five facts decide how to read that table.

**A translated x64 process pays for the walk, and not for the identity read.** Every column above is
ARM64. An ARM64 Windows runs an x64 image under its own emulation, so one machine measures both
architectures. Windows supports both, so this is a supported configuration. Measured on 2026-08-18:

| Read | Windows 11, x64 emulation |
|---|---|
| `code_identity` | 301 us |
| `identity_match` | 73 us |
| `tracer_state` | 1.3 us |
| `code_regions` | 722 us |
| `code_origin` | 744 us |
| one worker cycle | 1.8 ms |

The walk costs the most, because it is a loop of system calls and the translator charges for each
one. The identity read costs less than the ARM64 column does, because it spends its time inside a
library that runs natively whatever the caller is. A host that ships an x64 image to an ARM64
Windows therefore pays about 1.5 cycles, and `tests/platform/README.md` records what its detectors
answer.

Rosetta gives the same shape on macOS, and it is not a supported configuration: macOS runs on ARM64
alone, so an x86_64 macOS build carries no promise. Measured on 2026-08-18 and kept as a note rather
than a budget, `code_regions` cost 429 us against 58 us native, and the identity read did not move.

**The Windows column carries a wider spread than the others.** A virtual machine produced it, and no
other column. Three runs on the same guest gave 296 us, 416 us, and 297 us for one `code_identity`,
and 411 us, 540 us, and 400 us for one `code_regions`. The table holds the two runs that agree, and
a physical host has still to confirm them. The gaps table in `tests/platform/README.md` records
that.

**The worker reads the identity twice on each cycle.** Platform trust reads `code_identity` and
expected identity reads `identity_match`, and each detector reads for itself. The pair is 82
percent of the macOS cycle. A cache inside one cycle would remove that, and it would also let one
detector answer with what the other saw, so v1 pays it. The same pair is 32 percent of the Windows
cycle, where the two address-space walks cost more than the identity does.

**The Android column above is a shell binary, which maps no archive.** Its identity read stops at
the gap, so the whole route is unmeasured there. The instrumented harness measures an application
process, which is what a host runs: one identity read costs about 510 us, and one worker cycle
costs about 2.4 ms. The cycle is more than the reads above because a real application maps far more
regions, and `code_regions` and `code_origin` each walk the whole mapping table. Reading it once
for both would nearly halve the cycle, and no measurement asks for that yet.

The harness reports the fastest call, and the `cost` examples report a mean. The two run in
different processes: an example owns its process, and the harness shares one with every other
instrumented test, including the control that starts a Fidelity runtime. A mean would measure that
worker as well, and it would move with the order that JUnit picks. Even the fastest call moves on
an emulator, which produced single cycles of 5.8 ms and 10.8 ms, so
`HarnessTest.the_identity_read_stays_inside_its_recorded_ceiling` holds ceilings of 4 ms and 20 ms.
They catch a regression of one order rather than state the budget.

**The iOS reads are nanoseconds because the image names no team.** The walk finds the signature,
finds no entitlements slot, and stops. An image that names a team adds a scan of a small plist.
That figure is unverified, because the simulator refuses to launch any image that carries the
entitlement. Measured on 2026-08-18, the refusal holds for a bare binary and for an installed app
bundle, and for an ad-hoc signature and a real developer certificate alike, because a simulator has
no provisioning mechanism. A device closes it. See [verification](05-verification.md).

The first call is separate, and two platforms charge a large one. macOS costs between 4 ms and 8 ms,
because the Security framework loads and fills its caches once. Windows costs the same order for the
first `code_identity`, between 4 ms and 8 ms across three runs, because `WinVerifyTrust` builds and
validates a certificate chain. It also costs about 780 us for the first `code_regions`. `start()`
pays both, and they are the figures a host notices. Every first call on the other three platforms
costs under 130 us.
