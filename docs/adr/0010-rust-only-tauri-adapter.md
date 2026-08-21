# ADR-0010: Keep Tauri access in Rust

- Status: accepted
- Date: 2026-08-20

## Decision

Fidelity supplies `tauri-plugin-fidelity` as an independent Rust crate. Its setup hook starts one
`fidelity::Builder` and stores the returned `Handle` in Tauri state.

The `FidelityExt` trait gives Rust code `fidelity_handle()` and `ensure_fidelity_allowed()`. The
crate exposes no WebView command, event, JavaScript package, permission, or capability.

The facade and the Tauri adapter each follow SemVer. The adapter stays outside the production
workspace, so Tauri does not enter a default Fidelity build.

## Why

The runtime must start during the host lifecycle. A small setup hook gives Tauri hosts that
placement without a second runtime contract.

A WebView is outside the Rust trust boundary. It must not read a report, change policy, or report a
host observation through the adapter.

Tauri has an external dependency tree. An independent workspace keeps that tree outside the
security library and preserves its default dependency property.

## Consequences

- A Tauri host installs `init(fidelity::new())` on its application builder.
- Rust code uses `FidelityExt` before each protected operation.
- A failed Fidelity start fails the Tauri setup phase.
- A new adapter item changes its locked public surface and follows SemVer.
- A WebView integration needs a new product decision and an ADR that supersedes this decision.
