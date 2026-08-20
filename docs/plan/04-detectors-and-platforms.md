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
  reads no content. A redirected call is a separate question, and the
  [dispatch detector](#dispatch-targets) answers it. That detector is `Instrumentation`, not
  `Integrity`, because a redirected call is a hook.

### Image identity tiers

**Platform trust** needs no host input. The operating system reports whether the running image is
signed and anchored to a key the machine trusts. It proves that a trusted party signed the image. It
does not prove that the host application signed it.

**Expected identity** is a value the host supplies. Fidelity never learns it from the running bytes
it is meant to verify. It is the only local input that detects pre-start repackaging.

| Platform | Platform trust | Expected identity that the host supplies |
|---|---|---|
| Windows | `WinVerifyTrust` chain validation | signing certificate SHA-256, taken from the Authenticode signer |
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

Windows holds a trap of the same kind, and the name is what sets it. The value that Windows tooling
calls a thumbprint is not the value that Fidelity takes. Checked against the .NET reference on
2026-08-13: `X509Certificate2.Thumbprint` always uses SHA-1, and the certificate user interface
prints that same value. `AuthenticodeThumbprint` holds a SHA-256 digest of the signer certificate.
The Android tier already takes that form, so the two platforms state one kind of value. A SHA-1
thumbprint has 40 characters, so it fails where the host builds it and never reaches `start()`.

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
excluded. Every integrity detector must have clean and hostile test cases for relocations,
packaging transforms, JIT runtimes, late legitimate loads, startup races, and a baseline that
exists before `start()`.

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
guidance rather than release tests. It states which ordinary tools a host should expect a finding
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
reason below, and the clean control that a compiler produces has now run here.

That control is the x64 emulator of an ARM64 Windows, and it reports. Measured on 2026-08-18, on
Windows 11 Pro build 10.0.26200: an x64 build of the same example holds 1052672 bytes of unaccounted
executable memory across 4 regions, on every run, and the ARM64 build of it holds none. The
translator writes code that no file backs, which is what a manual mapper does, so no rule separates
the two. A host that ships an x64 image to an ARM64 machine therefore gets this finding on every
clean run, and that is a second reason the strength cannot rise. The runtime baseline stays clean in
the same process, because the translator maps its cache before `start()` reads the baseline.

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

## Dispatch targets

A loader resolves an imported call through a table of pointers. A hook that rewrites one entry
redirects the call to code that already exists. It maps no new executable region, so the runtime
baseline below reports clean, and the table holds data rather than code, so unaccounted code does
not reach it either. This detector reads that table, and reports an entry that points somewhere
else than at start.

| Platform | Source | Hostile control |
|---|---|---|
| Linux | the jump-slot relocations of the main image, through `dl_iterate_phdr` | `hook.c`, which points `memcpy` at `memmove` |
| Windows | the import address table of the main module, through `GetModuleHandle` and the PE headers | `iat-hook-windows.c`, which redirects a startup import from outside |
| macOS, iOS | the non-lazy symbol pointers of the main image, through `_dyld_get_image_header` and the Mach-O sections | `hook-macos.c`, which points `memcpy` at a forwarder of its own |

The detector reads the main image alone, and the reason is the memory budget. A shared library can
hold thousands of dispatch targets, and the snapshot must stay bounded. Measured on Linux and
ARM64: a Rust main image holds about 80, and on Windows and ARM64 a Rust main module holds 71. The
main image is also the table that an attacker rewrites to intercept the host's own calls, so it is
the table worth reading first.

The comparison needs a table that the loader bound fully before the process ran. A table that the
loader binds on the first call rewrites its own entries later, which reads exactly as a hook reads.
Measured on Linux and ARM64 on 2026-08-19: a Rust main image, in a debug build and a release build,
carries `BIND_NOW`, so every entry holds its final value from before the process ran and a later
change arrived from outside. A main image that is not fully bound reports `Unsupported`, which
states the gap rather than a false clean. Windows resolves the static import table at load, before
the entry point, so it is always fully bound, and a delay-load import is a separate table that the
probe does not read.

Apple applies that same rule to its own two binding models, and the load commands of the image name
which one it uses. `LC_DYLD_CHAINED_FIXUPS` binds every import before the image runs and carries no
lazy table, so the probe answers. `LC_DYLD_INFO_ONLY` keeps the lazy pointers in `__la_symbol_ptr`,
so the probe reports `Unsupported`. A linker writes chained fixups from a deployment target of
macOS 13 or iOS 15, and the [v1 floor](#supported-targets) is macOS 15 and iOS 26, so an image that
meets the floor always carries them. Measured on macOS 26.5.2 and ARM64 on 2026-08-20: a chained
Rust image held 73 to 96 pointers in `__got` and no lazy table, and a classic image of the same
source held 2 non-lazy pointers and 72 lazy ones.

A redirected target is `Medium`, and `High` is closed rather than pending. The evidence is direct,
because a fully bound table does not rewrite its own entries. It stays below `High` for the reason
the signal model states: an attacker inside the process rewrites the table and the comparison logic
together, so the signal has a meaningful user-mode bypass. Measured on 2026-08-19, on ARM64: the
`memcpy` slot of a Linux main image, redirected to `memmove`, left the runtime baseline clean over
40 seconds and this detector caught it after 5.6 seconds. On Windows, an external
`WriteProcessMemory` redirected a startup import of the running subject to another loaded function,
and this detector caught it after 7.0 seconds while the baseline stayed clean, because the import
table sits in a data section. On macOS and on iOS, an agent that the loader mapped before the
process ran redirected the `memcpy` pointer of the main image to a forwarder of its own, and this
detector caught it after
5.8 and 5.1 seconds while the baseline stayed clean over 40 seconds. So this detector catches a hook
that maps no new executable region.

Three clean controls decided the rule, and each one ran on Linux and ARM64 on 2026-08-19. A plain
process, a Rust process, and a Python process with SQLite and OpenSSL, which holds 6749 targets,
each reported no target that points outside every loaded object. Lazy binding moved 6 of 12 targets
in a plain C build, so a rule that read "the target changed" would report every process that makes
a call, which is why the detector reads a fully bound table only. A benign `dlopen` after start
loaded a library and moved 4 targets, and none of them pointed into the library it loaded, so a
plugin load does not trip the detector.

Two coverage limits follow, and both are deliberate. A redirect to another address inside an object
that was already loaded, such as `memcpy` to `memmove`, reports here, but a redirect that the
attacker maps as new executable memory is the runtime baseline's finding instead, because the
trampoline is a region that arrived after start. A hook of a shared library's own dispatch table is
out of scope, because the snapshot reads the main image alone.

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
still be rooted. A system that reports a development build is not rooted by that fact alone. The
detector states what the system says about itself, and the strength states how much that is worth.

The first limit is measured rather than argued. Measured on 2026-08-18, on the Android 36 Play Store
image and ARM64: Magisk 25.2 patches the ramdisk, `magiskd` then runs as root, and `/system/bin/su`
appears. Both properties stay as they were, so this detector reports `clean` on a system that now
holds a root daemon. The tool takes the privilege and leaves the statement alone.

iOS can answer this question and no code exists yet. A jailbreak weakens the same kernel guarantees
that the identity probe already reads, so the mechanism is reachable. It waits for a control that
produces a jailbroken system.

macOS, Windows, and Linux report `Unsupported`. Each one grants its user administrator rights or
root by design, so this category has no privilege boundary there to report the loss of.

## Machine host

A virtual machine monitor sits below the operating system, so it reads every byte that the process
holds and stops it at any instruction. No check inside the process sees that happen. The kernel does
see the boundary, and this detector reads what the kernel states about it.

| Platform | Source | Hostile control |
|---|---|---|
| macOS | `kern.hv_vmm_present`, through `sysctlbyname` | a macOS guest, which `tests/platform/vm/macos/` builds |
| Linux | the firmware identity, which the kernel writes under `/sys/class/dmi/id/`, and the paravirtual bus under `/sys/bus/virtio/devices` | the Linux guest, and a second monitor that ships no firmware identity |
| Windows | the same firmware identity, through `GetSystemFirmwareTable` with the `RSMB` provider | the Windows guest |
| Android | `ro.boot.qemu`, `ro.build.characteristics`, and `ro.hardware`, through the property store | an emulator image |

macOS holds both controls. Measured on 2026-08-18: this development machine reports 0 and the
detector reports clean, and macOS 26.6.2 inside a Virtualization.framework guest reports 1 and the
detector reports `Medium` and denies the operation. The guest needs no account and answers no
network, because a launch daemon that the host writes into its disk runs the control at boot.

Linux, Windows, and Android hold the hostile control alone, because this project owns no bare-metal
Linux, no bare-metal Windows, and no physical Android device. Measured on 2026-08-19: the Linux
guest and the Windows guest each report `QEMU` and `QEMU Virtual Machine`, and the Android 37
emulator reports `ro.boot.qemu=1`. All three report `Medium` and deny the operation.

Linux and Windows read the same two fields of the same DMTF structure, so both call one reader in
`fidelity-formats`, and one list of names decides for both. The list is the `dmi_vendor_table` of
systemd, read on 2026-08-19, without two of its entries: `Amazon EC2` and `Oracle Corporation` each
name real hardware as well. An unknown name reports nothing, which costs coverage and never costs a
clean run.

Linux reads a second source, and a measurement is the reason. Measured on 2026-08-19: an ARM64
Linux guest under Virtualization.framework, which OrbStack runs on this development machine, exposes
no `/sys/class/dmi` at all and holds twelve virtio devices. A firmware name alone would say nothing
there. The two sources cover different parts of one question and neither states that the other is
absent, so they can never disagree and one capability reads both.

The name decides the answer, and a near neighbor gives the opposite one. `kern.hv_support` states
that this machine can host a guest, and ordinary Apple Silicon hardware reports 1 there, so a check
on that name would report every clean Mac. Apple reads `kern.hv_vmm_present` in its own content
cache, which refuses to run when that value reports a guest.

This is not the processor flag that the excluded-mechanisms table above rules out. That flag states
whether the processor offers virtualization, and this value states whether something uses it.

A reported virtual machine is `Medium`, and `High` is closed rather than pending. Both `Medium`
clauses apply, and either one alone would decide it. The benign case is common: a developer who runs
the whole system in a guest reports it on every clean run, and so does a build machine, and so does
a host that ships to a virtual desktop. The bypass is meaningful on every platform: the system
states this about itself, in a value or a file or a property, and a root actor on the guest writes
what it likes there.

Two coverage limits follow, and both are deliberate. A system that reports the hardware may still
run under a monitor that hides itself, because the same root actor rewrites the answer. A system
that reports a monitor is not under attack by that fact alone. The detector states what the system
says about itself, and the strength states how much that is worth.

iOS can answer this question, and no code exists yet. It holds neither control, and a measurement
decided that rather than caution. Measured on 2026-08-19 in an iOS 18.5 simulator: a process there
reads the kernel of the Mac that hosts it, so `kern.hv_vmm_present`, `hw.machine`, and `hw.model`
each report what the Mac reports and none of them describes the simulator. A rule that separated a
simulator from a device would rest on what this project believes a device reports, and this project
holds no device. The probe crate states that.

## The user interface

Every other category reads the operating system. This one cannot, and a measurement decided that
rather than a preference.

Measured on Android 37 on 2026-08-19. A library reaches an application context by itself, through a
call on a list that Google owns. What that context then reaches splits in two:

- `WindowManager` declares 41 methods, and only the two screen-recording ones touch this question.
  Nothing states that another application draws above this one. That evidence is
  `MotionEvent.FLAG_WINDOW_IS_OBSCURED`, which arrives on a touch that a `View` receives, and a
  library holds no `View`.
- `addScreenRecordingCallback` registers from an application context, and the SDK source states its
  anchor as any activity of the registering uid. So a library inside the host process reads what the
  host reads. It needs a permission in the host's manifest, and it needs API 35 against a floor of
  34.

Both remaining package lists are weak evidence, and the excluded-mechanisms table above already
rules the accessibility one out. A clean emulator enables no accessibility service and holds 17
packages that request permission to draw over another application, nearly all of them Google's own.

So the host reads it, and `Handle::report_ui_abuse` takes the report. The host supplies a fact, and
Fidelity decides the strength, the evidence, and the action, because a host that stated its own
strength would be stating policy.

| Observation | Strength | Why |
|---|---|---|
| an overlay | `Medium` | direct evidence, and a screen dimmer, a caption window, and an assistive overlay all raise the same flag |
| a screen capture | `Low` | a person who records their own screen is the ordinary explanation |

The call records the finding at once, so a configured `Deny` latches before it returns and
`ensure_allowed()` denies immediately. `Callback` and `Crash` run host code, and only the worker
runs host code, so those two reach the report on the worker's next cycle. The initial scan takes the
same route. A queue holds one cycle of reports and never a history, so a host that reports without
stopping never grows the memory of the process it protects.

The state slot rests at `NotRun` until a host reports. That states the absence of a report, which is
what it is, and the signal model above forbids reading it as a clean result. No scan reaches this
detector, so nothing else can move it.

This category has no capability and no platform row, and the coverage matrix in
[delivery](06-delivery.md#capability-coverage) states that. Its controls run on any machine, because
no operating system takes part.

## Supported targets

The v1 floor is:

| Platform | Minimum | Architectures and notes |
|---|---|---|
| Android | Android 14 (API 34); target API 36 | physical ARM64, and x86_64 and ARM64 emulators |
| iOS | iOS 26; build with Xcode and iOS SDK 26 | physical ARM64 plus supported simulators |
| macOS | macOS 15 | ARM64 only, on Apple Silicon. No Intel Mac is in scope. |
| Windows | Windows 11 25H2 or later | ARM64 and x86_64 |
| Linux | glibc 2.34+ on supported vendor kernels | ARM64 and x86_64; Ubuntu 24.04 and 26.04 are the primary test targets |

Only a vendor-supported security release is eligible. The [release gate](05-verification.md)
revalidates every floor. Linux musl, older OS releases, and other Apple platforms are not v1.

macOS is the one platform with a single architecture, and that is a scope decision rather than a
technical limit. No Intel Mac is in scope, so Fidelity makes no promise about an x86_64 macOS build,
and none about one that runs under Rosetta. The probe code carries no architecture condition, so an
x86_64 macOS process still reads the same facts. No control covers it, and it carries no promise.

The same public API and the same semantics apply everywhere. Capability metadata expresses what a
platform lacks. Conditional public types do not. A release cannot call a platform complete while a
required category is a placeholder.
