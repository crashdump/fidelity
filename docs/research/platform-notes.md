# Condensed platform research notes

Consolidated 2026-08-07. "Candidate" means worth testing. Revalidate each load-bearing claim on the
supported OS and toolchain before you implement or release a detector.

## Cross-platform selection rules

- Prefer kernel- or loader-sourced facts over user-writable process metadata, but document that a
  same-process attacker can still intercept the query or response.
- Prefer structural evidence about the current process over tool names, ports, paths, parent
  processes, or timing.
- Treat a clean control matrix as part of detector implementation. The matrix includes security
  products, accessibility tools, development configurations, emulation layers, and enterprise
  policy.
- An API error is a health finding, not a clean result. A missing API is `Unsupported`, not a
  detection.
- Do not infer authenticity from a checksum, or from a signature by any certificate.
- Do not convert environment posture into hostile activity without a valid benign-base-rate
  argument.

## Apple: iOS and macOS

| Candidate or constraint | Why it survives the survey | Validation needed |
|---|---|---|
| Resolve the owning image by a known address | Dyld image index zero can change under insertion | verify public API behavior across floors and packaged app forms |
| Current executable-region provenance | Anonymous executable mappings and changed protections can reveal injection/hooking | baseline JIT, Rosetta, WebKit, and entitlement cases |
| Code-signing status and distribution category | OS-backed status is stronger than bundle-path heuristics | separate public API from SPI and App Store review risk |
| Multiple independent debug-state sources | Inconsistent results can reveal hooking; some state is monotonic | verify iOS sandbox access and macOS false positives |
| External-modification counters | Directly describe task-port and remote-thread interactions | establish benign callers and OS stability |
| Loaded-image and sandbox-semantic compromise checks | More resilient than a static jailbreak path list | test modern rootless and randomized-root tools |

Avoid treating static paths, URL schemes, parent PID, fixed Frida ports, or function-prologue shapes
as decisive. Frida can map images without dyld, modern fixups invalidate legacy import-table
assumptions, and sophisticated bypasses can hide all user-mode queries.

The `Virtualization` question on macOS is settled, and the
[plan](../plan/04-detectors-and-platforms.md#machine-host) owns it. It survived this survey as a
candidate, and the measurement moved it out of these notes.

Primary starting points: [Apple QA1361](https://developer.apple.com/library/archive/qa/qa1361/_index.html),
[Apple platform security](https://support.apple.com/guide/security/welcome/web), and
[OWASP MASTG iOS resilience testing](https://mas.owasp.org/MASTG/0x06j-Testing-Resiliency-Against-Reverse-Engineering/).

## Linux (glibc)

| Candidate or constraint | Why it survives the survey | Validation needed |
|---|---|---|
| `/proc/self/maps` and `smaps` provenance | Direct view of executable mappings, file backing, and private dirty pages | kernel/vendor differences, deleted files, JITs, containers |
| Loader enumeration cross-checks | Divergence may expose hidden or manually mapped objects | glibc version range and legitimate loader behavior |
| Tracer state from `/proc/self/status` | Cheap direct tracer evidence | namespaces, procfs availability, hostile rewriting |
| Import/relocation target validation | Can identify redirection outside expected images | lazy binding, IFUNC, audit/preload, sanitizers, security agents |
| Environment and loader-preload state | Useful context for injection | never high-strength alone; environment may be intentionally configured |
| fs-verity digest and keyring signature status | The only kernel-anchored image identity Linux offers. `FS_IOC_MEASURE_VERITY` returns a digest the kernel computed, and the kernel verifies the built-in signature against the `.fs-verity` keyring on open. | availability is the blocker: RPM can ship the metadata, but Fedora does not install the enabling plugin by default and Debian/Ubuntu have no dpkg integration. Expect `Unsupported` on stock desktops and real coverage on immutable and hardened systems. |

Do not ship timing checks, self-`ptrace` fork guards on desktop, or raw RWX presence as decisive.
Container/VM evidence describes deployment posture, not necessarily an attacker. In-memory versus
disk code comparison requires relocation and legitimate-runtime-write analysis per binary.

Primary starting points: [proc pid maps](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html),
[proc pid status](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html),
[dl_iterate_phdr](https://man7.org/linux/man-pages/man3/dl_iterate_phdr.3.html), and
[fs-verity](https://docs.kernel.org/filesystems/fsverity.html).

## Android

Android shares Linux mapping and tracer primitives but adds ART/JNI, package, SELinux, application
sandbox, emulator, and root-management realities.

| Candidate or constraint | Why it survives the survey | Validation needed |
|---|---|---|
| Native mapping and loader checks | Instrumentation agents commonly introduce executable mappings | ART, JIT, WebView, OEM, ABI, and emulator baselines |
| Package/signing identity supplied by the host integration | Repackaging evidence is meaningful when pinned to the expected app | signing rotation and Play distribution paths |
| Root-management process/mount/security-state evidence | Can reveal compromised platform semantics beyond path lists | Magisk/Zygisk variants, namespaces, OEM differences |
| Emulator properties | Useful for a host that elects to act on virtualization | physical-device farms and OEM false positives |
| Loopback instrumentation protocol probe | Stronger than a fixed port number when bounded locally | protocol changes, timeout, and no off-device traffic |

Static root paths, build properties, package names, and port numbers are supporting evidence only.
Remote Play Integrity, or another attestation service, belongs to the host, not to Fidelity.

**A library reaches an application `Context` on its own, and the route is not a supported one.** The
`UiAbuse` category needs a system service, a system service needs a `Context`, and
[delivery](../plan/06-delivery.md) states that the public API gains no Android-only field. Measured
2026-08-13 on two images, Android 36 with `release-keys` and Android 37 with `dev-keys`:
`ActivityThread.currentApplication()` and `AppGlobals.getInitialApplication()` both return the
application, and both give a working window service and package manager. The platform logged
`api=unsupported ... using reflection: allowed` for each call, on both images.

`unsupported` is the greylist, so the call is allowed at every target SDK and only warns. That is a
list Google owns and changes per release, so the route works until it does not, and no compile ever
reports the change. Weigh that against `JNI_GetCreatedJavaVMs`, which the probe already uses and
which `libnativehelper.so` exports as a documented interface. The two are not the same kind of
dependency. This also means the `identity` route could have used `PackageManager`, and it does not
need to: the archive walk holds, and it takes no greylist.

**What that `Context` then reaches decides the category, and it splits in two.** Measured on
Android 37, 2026-08-19. `WindowManager` declares 41 methods, and only `addScreenRecordingCallback`
and its remover touch this question, so no interface states that another application draws above
this one. That evidence is `MotionEvent.FLAG_WINDOW_IS_OBSCURED`, which reaches a `View` that the
host owns. The screen-recording interface is different: it registers from an application context
with `DETECT_SCREEN_RECORDING`, and the SDK source states its anchor as any activity of the
registering uid, so a library inside the host process reads what the host reads. It needs API 35
against a floor of 34. Two package lists stay weak: a clean emulator enables no accessibility
service and holds 17 packages that request `SYSTEM_ALERT_WINDOW`, nearly all of them Google's own.

Primary starting points: [Android security best practices](https://developer.android.com/privacy-and-security/security-best-practices),
[Android app signing](https://developer.android.com/studio/publish/app-signing), and
[OWASP MASTG Android resilience testing](https://mas.owasp.org/MASTG/0x05j-Testing-Resiliency-Against-Reverse-Engineering/).

## Windows

| Candidate or constraint | Why it survives the survey | Validation needed |
|---|---|---|
| Documented debugger APIs plus selected process information | Direct debug-object/port evidence is stronger than PEB heuristics | x86_64/ARM64 behavior and anti-anti-debug bypasses |
| Loader view versus kernel-backed mapping view | Can expose hidden modules or manual mapping | loader races, WOW/emulation, enterprise injectors |
| Executable-region provenance and thread start correlation | More specific than raw private/RWX memory | GPU drivers, runtimes, DRM, EDR, accessibility tools |
| Authenticode trust plus expected signer pin | Establishes both platform trust and application identity | certificate rollover, catalog handling, offline behavior |
| Kernel-sourced own-process path | Avoids trusting a writable PEB as identity | path normalization and packaged applications |
| Existing mitigation-policy readback | Useful posture/tamper evidence without enabling hardening in v1 | enterprise policy overrides and supported policy masks |

`WinVerifyTrust` must be non-interactive, cache-only, and bounded. During the synchronous initial
scan, inability to complete safely becomes a detector-health finding rather than an unbounded
startup stall. Results must distinguish tamper, no signature/catalog signing, revocation offline,
expiry, and enterprise trust.
Do not use the PE checksum as a security control. Do not enforce parent-process checks, generic
ntdll hook detection, raw RWX/private-executable presence, or VM CPUID bits without discrimination.
The latter also identifies ordinary VBS, Hyper-V, WSL2, and Windows Sandbox environments.

Proactive process mitigations may be valuable after v1, but several are irreversible or break JIT,
security, input, accessibility, and shell integrations. They require a separate opt-in design and
compatibility program.

Primary starting points: [GetProcessMitigationPolicy](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocessmitigationpolicy),
[WinVerifyTrust](https://learn.microsoft.com/windows/win32/api/wintrust/nf-wintrust-winverifytrust),
and [VirtualQuery](https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-virtualquery).

## Open empirical work

1. Measure benign executable-memory and hook baselines across supported runtimes and enterprise
   security products on every desktop target.
2. Validate all Apple APIs against public SDK availability, store policy, physical iOS hardware,
   and the minimum OS floor.
3. Build rooted/jailbroken and clean mobile device matrices that are reproducible for releases.
4. Validate Windows ARM64, emulation, packaged-app, signature/catalog, and loader edge cases.
5. Validate glibc/procfs behavior across supported vendor kernels and containers.
6. Re-check platform floors and all standards links before the first release.
