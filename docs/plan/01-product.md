# Product contract

## Purpose

An application embeds Fidelity to detect and respond to runtime tampering. Applications have
different risk appetites, so Fidelity reports the evidence and lets the host select a response for
each broad security category.

The library must:

- detect useful user-mode signals, and state their evidential strength and platform limits;
- make findings available through a small, stable, typed Rust API;
- apply a configured local response with no remote service;
- behave consistently on Android, iOS, macOS, Windows, and glibc Linux; and
- make false positives, detector failures, and unsupported capabilities visible.

## v1 categories

| Category | Question |
|---|---|
| `Integrity` | Has executable code, a trusted image, or process state been modified unexpectedly? |
| `Debugging` | Is, or has, a debugger or tracer interacted with the process? |
| `Instrumentation` | Is runtime hooking, injection, or dynamic instrumentation present? |
| `DeviceCompromise` | Is the OS security model weakened by root, jailbreak, or equivalent compromise? |
| `Virtualization` | Does the application run in an emulator, simulator, VM, container, or analysis environment? |
| `UiAbuse` | Does another application read or drive this application's user interface? |

The categories are broad. v1 has no per-detector configuration and no custom category
registration. `Category` is `#[non_exhaustive]`, because the project may add a category after v1.

The category is the configuration boundary for a compatibility reason, not only a simplicity one.
The detector set is closed but it grows. A host that pinned an action to each detector would get
silent under-coverage on upgrade, because a new detector would carry no configured action. A
category-level action covers every detector that a later release adds.

`UiAbuse` covers overlays, hostile accessibility services, screen capture, and screen recording.
These attacks need platform user-interface APIs, so the category is mobile-first. It reports
`Unsupported` where a platform gives no equivalent surface.

## v1 responses

| Action | Contract |
|---|---|
| `Report` | Publish the finding and keep running. This is the default for every category. |
| `Deny` | Permanently latch a process-wide denial that the host checks with `ensure_allowed()`. |
| `Callback` | Invoke the host's synchronous callback after the finding and policy state are latched. |
| `Crash` | Abnormally terminate the current process immediately, without an unwind or cleanup. |

`Crash` reaches the platform as an abnormal termination, so it appears in crash reports and in store
metrics. A host that selects it must expect its crash-free-session rate to move. `Crash` never fires
on a detector-health finding: that finding describes Fidelity, and terminating the host process
because our own check failed would turn a transient error into a denial of service.

Fidelity reports every finding, including a finding below the action threshold. Actions do not
compose, and each category has one action. A callback is the extension point for an application that
needs a custom or multi-step response. A host that reaches its own verdict there calls
`Handle::deny()` to latch it. That call only adds a denial, so it is not an off-switch.

## Explicit non-goals

v1 does not provide:

- a remote control plane, telemetry collector, attestation service, or network client;
- storage or a durable audit log;
- authenticated findings, or protection from an attacker who already runs inside the process;
- runtime plugins, third-party detectors, presets, scores, decay, or signal aggregation;
- a JavaScript or webview API, or a frontend event stream, for Tauri;
- a C ABI or any other FFI entry point;
- proactive OS hardening, or secret erasure;
- obfuscation. Fidelity does not rewrite the host application. It complements a compiler-based
  hardening tool, and it does not replace one; or
- a network and TLS category. The project may consider it after v1.

A later network category would take connection and certificate context from the host. It would not
give Fidelity ownership of the application's sockets.

## Meaning of v1

"Implemented on a platform" means a real backend exists and passes representative clean and hostile
tests on supported systems. A mock, a compiling placeholder, and an `Unsupported` result do not
count. v1 is complete when all five target platforms meet that definition.
