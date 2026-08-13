# Detectors and platforms

## Signal model

`SignalStrength` describes the evidential quality of one finding, not impact or severity.

| Strength | Meaning |
|---|---|
| `Low` | Ambiguous posture, health failure, or a heuristic with common benign explanations. |
| `Medium` | Direct evidence with known legitimate cases or a meaningful user-mode bypass. |
| `High` | Direct evidence whose benign explanation is structurally rare on the supported target. |

The engine keeps the strongest observation only. It does not add weak signals, calculate a score,
decay evidence, or escalate repeated detector failures. Evidence is typed and detailed enough to
explain the mechanism without exposing application secrets.

Each scan gives a detector exactly one outcome:

| Outcome | Meaning |
|---|---|
| `NotRun` | No scan reached this detector yet. Every state slot starts here. |
| `Clean` | The check ran and found nothing. |
| `Finding` | The check ran and found something. It carries a `SignalStrength` and typed evidence. |
| `Unsupported` | The check cannot run here. It states why, and it never creates a finding. |

`NotRun` and `Unsupported` are metadata, and neither enters policy. `NotRun` must never read as a
clean result: the initial scan covers the cheap detectors only, so a host that reads a slot before
the first full scan sees absent coverage, not a healthy one. An unexpected API failure is neither
`Clean` nor `Unsupported`. It is a `Low` detector-health `Finding`. A panic in a detector gets the
same treatment, and the worker catches the unwind and continues. A repeated panic never disables
the detector, because a detector that switches itself off is a target.

## Excluded mechanisms

No detector may use these, whatever the platform. The
[research notes](../research/platform-notes.md) hold the candidate mechanisms worth testing. A
detector enters v1 only after the tests in [verification](05-verification.md) establish its strength
on every platform that enables it.

| Category | Never decisive evidence |
|---|---|
| `Integrity` | a generic parent check; a checksum presented as authenticity; an undocumented byte comparison with no clean baseline; an Apple signature check with no requirement, because the kernel stops a modified image before it runs, so the check only ever passes |
| `Debugging` | timing tricks and exception abuse that destabilize the host |
| `Instrumentation` | a name or a port as high-strength evidence; an enterprise security hook with no measured discrimination; the Apple dyld image list, because the hardened runtime already refuses an inserted library, and a later `dlopen` leaves the list in order; an absolute count of unattributed executable memory on Apple, because a clean process holds gigabytes of it |
| `DeviceCompromise` | a static path list as decisive evidence; remote attestation inside the library |
| `Virtualization` | the Windows CPUID hypervisor bit, because it also identifies ordinary VBS, Hyper-V, WSL2, and Windows Sandbox |
| `UiAbuse` | the presence of an accessibility service as decisive evidence, because assistive technology is a legitimate and protected use |

Platform code must prefer documented or stable OS interfaces. Use private/SPI or undocumented APIs
only when there is no adequate supported alternative, the call is isolated behind a capability,
failure is safe, and release testing covers the supported OS range.

## Integrity baseline contract

Integrity checks distinguish two baselines:

- **Image identity** answers whether this is the expected image. It has the two tiers below.
- **Runtime baseline** records the mappings and the protections that the operating system reports
  during the synchronous initial scan. It reports a region that arrived after start, and a region
  that start mapped as read and execute and that something has made writable. It detects later
  change but cannot prove that launch was initially clean. It does not detect code that an attacker
  replaces inside a mapping that keeps both its first address and its protection, because a scan
  reads no content. Dispatch targets are not recorded yet.

### Image identity tiers

**Platform trust** needs no host input. The operating system reports whether the running image is
signed and anchored to a key the machine trusts. It proves that a trusted party signed the image. It
does not prove that the host application signed it.

**Expected identity** is a value the host supplies. Fidelity never learns it from the running bytes
it is meant to verify. It is the only local input that detects pre-start repackaging.

| Platform | Platform trust | Expected identity that the host supplies |
|---|---|---|
| Windows | `WinVerifyTrust` chain validation | Authenticode signer thumbprint |
| macOS | `SecCodeCheckValidity` against `anchor apple generic` | team identifier, as a code requirement string |
| iOS | implicit, because the kernel enforces signing and exposes no equivalent API | team identifier, read from the App ID prefix |
| Android | none, because any self-signed certificate is valid | signing certificate SHA-256, through `hasSigningCertificate` |
| Linux | fs-verity digest and keyring signature status, where the deployment enables it | content digest of stable executable content |

iOS takes a different route, and the SDK decides it rather than a design choice. Checked against
the iOS 26 SDK on 2026-08-10: the Security framework there declares neither `SecCode` nor `SecTask`,
so `SecCodeCheckValidity` and `SecCodeCopySigningInformation` do not exist. Platform trust therefore
reports `Unsupported` on iOS, and that tier creates no finding there. The team identifier comes from
the entitlements that the image carries, which the probe reads out of the embedded code signature.
Splitting an App ID at its first full stop is a guess, so the prefix counts only at the length that
Apple issues. Any other value reports no team, which is a gap, and never a wrong team.

Android reads the certificate out of the archive that the process runs from, and not through
`PackageManager`, because that interface needs a `Context` that a library cannot reach. Selecting
that archive is exact, not close. Measured on Android 37 on 2026-08-10, a Chrome process maps 58
archives, and two of them sit under `/data/app/`, so a search for the first one answers with the
wrong file and a wrong archive gives a wrong identity with no error. The rule takes the archive
whose install directory names the package that `/proc/self/cmdline` reports, and it reports a gap
when none does. An instrumented test compares the result against `PackageManager`, because the
route only holds while the two agree.

Expected identity is optional. Fidelity reports `Unsupported` with a stated reason when the host
supplies nothing, and the runtime baseline still runs. A call to `expected_identity()` makes the
check required. `ExpectedIdentity` therefore holds an explicit choice per platform: a value, or an
accepted `Unsupported`. If the choice for the target platform is absent, `start()` fails with a
typed error. A value that Fidelity cannot parse fails where the host builds it, so it never reaches
`start()`.

Fidelity ships no tool to produce these values. The host obtains them from its own signing and
build pipeline. On Android the value is the distribution signing certificate. That is not the upload
certificate when Play App Signing is in use.

The two tiers carry different strengths, because they answer different questions. A rejected
platform trust is `Medium`: a host that ships an ad-hoc or a self-signed build fails it on every
clean run, so the benign case is common. An unexpected identity is `High`: the host pinned the
value, so the running image is not the image the host shipped. Measured on macOS 26 and ARM64, a
repackaged image fails both, and an image that a second certificate of the same team signed fails
neither.

### Identity cross-checks

One guaranteed source derives the key for a
[guarded constant](03-runtime-and-api.md#guarded-constants).
Where a platform offers other independent identity sources, they run as `Integrity` detectors and
never enter the derivation. A disagreement between two sources is direct evidence that something
answers for the operating system, so it is a finding.

Mixing several sources into the key would be worse, not better. Each added source becomes another
way to break a legitimate install: one source that changes after an OS update makes every guarded
constant decrypt to garbage, silently, because a wrong key never reports an error. Linux also has
one source at most, so a mixed key would give a platform-specific promise. A detector reports
`Unsupported` where a source is absent, and the semantics stay the same everywhere.

Before `start()` returns, a backend validates the expected identity where the platform permits. A
mismatch is an `Integrity` finding, not a start error, so the host's configured action applies. The
backend then lets the loader complete documented relocations and fixups, excludes dynamic and JIT
regions, and captures fixed-size typed baseline data. The baseline has no public mutator, and it is
immutable after start. A platform may make its storage read-only as defense in depth. That is not a
trust boundary: a same-process or stronger attacker can patch the baseline or the comparison logic.

The probe identifies dynamic and JIT regions from operating-system mapping metadata. The host does
not declare them. A host-declared exclusion list would give an attacker a supported way to hide a
region, so v1 has no such input. Every runtime that generates code, such as a WebView, ART, or a
managed runtime, is a required clean control.

A scan reads the mappings in one forward pass, and it does not retry. A region that arrives below
the cursor after the cursor passed it is absent from that scan. The baseline is immutable, so the
next scan reports it, and a missed region costs one worker cycle rather than going missing for good.
A second pass would shorten that window and report a `Low` detector-health finding every time a
runtime mapped code between the two passes, so it would cost a false finding on every process that
holds a JIT. Evidence states which anchor the scan checked, and which regions or identities it
excluded. Every integrity detector must
have clean and hostile test cases for relocations, packaging transforms, JIT runtimes, late
legitimate loads, startup races, and a baseline that exists before `start()`.

## Tracer state

The kernel holds this state, so the detector reads it and adds nothing.

| Platform | Source | Hostile control |
|---|---|---|
| macOS | the `P_TRACED` flag, through `sysctl` with `KERN_PROC_PID`, which Apple documents in [QA1361](https://developer.apple.com/library/archive/qa/qa1361/_index.html) | `lldb` |
| iOS | the same flag, through the same interface, so both Apple systems share the body | `lldb` |
| Linux | the `TracerPid` field of `/proc/self/status` | `gdb` |
| Android | the same field, because Android keeps the Linux process filesystem. It needs no JVM handle. | a `ptrace` tracer |
| Windows | `CheckRemoteDebuggerPresent`, which asks the kernel about the debug port of the process | `controls/attach-windows.c` |

Windows offers a second call, and the probe does not take it. `IsDebuggerPresent` reads the
`BeingDebugged` byte of the process environment block, which is memory inside this process, so an
attacker who already runs here clears one byte. The call the probe takes asks the kernel, which is
the same source that the other four platforms read.

On each one, a clean run and the same binary under a debugger separate on that value.

A reported tracer is `Medium`, and `High` is closed rather than pending. One documented interface
answers, and an attacker inside the process replaces that answer at one call site. The signal model
above puts a meaningful user-mode bypass at `Medium` on its own, so no measurement lifts this
detector while one call site answers for it. A developer who debugs a build under test also trips
it on every run, which is a second reason for the same strength.

A false-positive survey across profilers, crash reporters, and enterprise agents is therefore host
guidance rather than release evidence. It states which ordinary tools a host should expect a finding
from. It cannot change the strength.

A platform that offers a second independent source adds a second detector, because a disagreement
between two sources is direct evidence that something answers for the operating system.

## Unaccounted code

A loader maps code from a file, so executable memory with no file behind it arrived another way.
That is the structural question this category asks, and it replaces every tool name and port.

Linux and Android read the mapping table of the process. A region counts as unaccounted when it is
anonymous, or when its file is gone. A region that the kernel named does not count.

Windows answers the same question, and it states the answer rather than implying it. `VirtualQuery`
reports the type of every region: an image section, another section, or private memory. A loader
maps a module as an image, so an image is accounted. Private memory is not. A section that is
neither needs one more question, because a file backs one kind and the page file backs the other,
and `GetMappedFileName` separates the two. That last pair matters: a manual mapper uses the second
kind, so a rule that accepted every section would miss it. The strength stays `Medium`, for the
reason below, and the clean control that a compiler produces has still to run here.

The measurement is what makes the rule usable, and it separates one compiler from another rather
than clearing them all. Measured on Android 37 and ARM64, a real runtime process names its code
caches `[anon_shmem:dalvik-jit-code-cache]`, so they stay distinct from anonymous memory. A plain
Debian process holds no anonymous executable region either, and the kernel vDSO is named.

Unaccounted code is `Medium`, and the clean control that decides the strength has run. Measured on
Debian and ARM64 on 2026-08-09, a warmed Node process holds one anonymous executable region, and
that region is writable, so it reads exactly as an injected agent reads. One compiler names its
code caches and another names nothing, so the rule reports a process that did nothing wrong. `High`
is therefore closed rather than pending. `fidelity-formats` keeps the capture as a fixture, and a
test holds the limit, so nobody removes it by accident.

Two coverage limits are deliberate. A library that a loader maps from a file does not trip this
detector, because a path list is not decisive evidence. A library that a loader maps before
`start()` is inside the first scan, so it reads as normal.

Apple needs a different mechanism, and the reason is measured rather than assumed. On macOS 26 and
ARM64 a clean process holds 17 executable regions, and only one to four of them resolve to a file
or to an image. The rest are the shared cache and the run-time allocations around it, and they
cover about 3.6 GB. Neither `proc_regionfilename` nor `dladdr` attributes them. An injected mapping
does appear, and it appears as one more entry in a list of thirteen that are already normal, so no
absolute rule separates it.

The signal that survives on Apple is therefore a change against a baseline that the process
captures at start, and not an absolute count. That is the runtime baseline below, which is why the
two tiers are separate.

## Runtime baseline

`start()` captures the executable regions of the process once, before the host runs any of its own
work. Every later scan captures another snapshot and compares. A region counts as added when its
first address sits inside no region of the baseline.

That rule survives a compiler that generates code, and the reason is measured. A region that grew
keeps its first address, and a compiler that writes code inside a pool it reserved earlier adds no
region at all. Measured on macOS 26 and ARM64: two different JavaScript hot loops add nothing,
while an injected mapping of 64 KiB appears at once.

The baseline is immutable for the life of the runtime. A baseline that a later scan could move
would prove nothing, because the attacker that maps the code also runs the scan.

A snapshot keeps a fixed number of regions. A process that maps more reports `Unsupported`, because
a snapshot that dropped a region cannot tell a new region from one it never kept. See
[state and budgets](07-state-and-budgets.md).

Code that arrives after start is `Medium`, and the clean control that decides the strength has run.
Measured on 2026-08-09:

- macOS 26 and ARM64: a plugin that the host loads with `dlopen` adds one region. A library that the
  dyld shared cache already holds adds none.
- macOS 26 and ARM64: a `WKWebView` adds four regions when the host creates it, and none afterwards.
  A navigation and a JavaScript hot loop each add none, because the compiler runs in another
  process. In-process JavaScriptCore adds none either.
- Debian and ARM64: a system library and a plugin each add one region.

The detector reported `Medium` on the legitimate plugin load after 5.7 s, and it carried the
evidence that the hostile control produces. `High` is therefore closed rather than pending: an
application that loads a plugin, a driver, or a locale is common, and this finding cannot separate
it from an injected agent.

A host that embeds a web view creates the view before it calls `start()`, or it accepts one finding
during startup. The cost lands once, so a later navigation reports nothing.

## System build

Root and jailbreak both take a privilege that the operating system holds against its own user. A
mobile system states whether its own build still keeps that privilege, and this detector reads that
statement. It names no tool, no package, and no path, because the excluded-mechanisms table above
rules a static path list out.

| Platform | Source | Hostile control |
|---|---|---|
| Android | `ro.debuggable` and `ro.build.tags`, through `__system_property_get` | a Google APIs system image, against a Play Store image |

Measured on 2026-08-10, on emulators: a Play Store image reports `release-keys` and
`ro.debuggable=0`, and a Google APIs image reports `dev-keys` and `ro.debuggable=1`. The same code
therefore has a clean control and a hostile control on one machine, which is why this detector
lands first in its category.

The rule names the two development markers, `test-keys` and `dev-keys`, rather than accepting
`release-keys` alone. No survey covers what every vendor writes in that field, and a clean control
that reports is worse than a hostile control that stays quiet.

A development build is `Medium`, and `High` is closed rather than pending. Both `Medium` clauses
apply, and either one alone would decide it. The benign case is common: an emulator, a developer's
own device, and an engineering build all report on every clean run. The bypass is meaningful: a
root user rewrites the property store, and the tools that take root do exactly that.

Two coverage limits follow, and both are deliberate. A system that reports a released build may
still be rooted, because the tool that took the privilege also rewrote what the system says. A
system that reports a development build is not rooted by that fact alone. The detector states what
the system says about itself, and the strength states how much that is worth.

iOS can answer this question and no code exists yet. A jailbreak weakens the same kernel guarantees
that the identity probe already reads, so the mechanism is reachable. It waits for a control that
produces a jailbroken system.

macOS, Windows, and Linux report `Unsupported`. Each one grants its user administrator rights or
root by design, so this category has no privilege boundary there to report the loss of.

## Supported targets

The v1 floor is:

| Platform | Minimum | Architectures and notes |
|---|---|---|
| Android | Android 14 (API 34); target API 36 | physical ARM64, and x86_64 and ARM64 emulators |
| iOS | iOS 26; build with Xcode and iOS SDK 26 | physical ARM64 plus supported simulators |
| macOS | macOS 15 | ARM64 and x86_64 |
| Windows | Windows 11 25H2 or later | ARM64 and x86_64 |
| Linux | glibc 2.34+ on supported vendor kernels | ARM64 and x86_64; Ubuntu 24.04 and 26.04 are the primary test targets |

Only a vendor-supported security release is eligible. The [release gate](05-verification.md)
revalidates every floor. Linux musl, older OS releases, and other Apple platforms are not v1.

The same public API and the same semantics apply everywhere. Capability metadata expresses what a
platform lacks. Conditional public types do not. A release cannot call a platform complete while a
required category is a placeholder.
