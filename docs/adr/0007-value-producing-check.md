# ADR-0007: Bind the host with guarded constants

- Status: accepted
- Date: 2026-08-08

## Decision

`ensure_allowed()` stays the advisory check, and a threshold tunes it, so a false positive costs
availability, not data. `guarded!()` is structural: it produces a value, not a decision. A build
step encrypts a host literal with a per-build key, and a started runtime derives the decryption key.
A wrong key returns a wrong value, not an error, so there is no branch to invert.

Only two inputs derive that key: the per-build key, and one guaranteed platform code identity in
[image identity tiers](../plan/04-detectors-and-platforms.md#image-identity-tiers). A heuristic
detector never gates a guarded constant. The inline expansion, the alphabet that keeps a wrong key
well formed, and the read cost are operational detail, and
[runtime and API](../plan/03-runtime-and-api.md#guarded-constants) holds them.

## Why

An attacker finds every `ensure_allowed()` call site by searching for one symbol, then inverts one
branch. Commercial products answer this: they move the host's own constants into the protected
component, so the application cannot run without it.

A wrong value cannot be tuned the way a threshold can. Gating on a heuristic would turn every false
positive into silent corruption, which the [security model](../plan/02-security-model.md) prevents.
Platform code identity is an OS-reported fact, so a repackaged application breaks and a hook
heuristic never does. Per-build variation removes the monoculture. A shared reader would undo all of
it, because one hook dumps every guarded constant at once.

## Consequences

- This supersedes the KDF-binding deferral. The stable input is OS-reported code identity.
- Coverage depends on which constants the host wraps. Fidelity does not rewrite host code.
- An attacker who runs the application once, or who hooks the identity call, recovers the value.
- Both key inputs ship inside the artifact, so the guard resists a repackage and not an extraction.
  The salt sits beside the ciphertext, and the operating system reports the identity to anybody.
- A build states its identity choice, and the running image must supply it. A build that binds to
  an identity fails its start where the image reports none, because a wrong key reports no error.
  Linux without fs-verity, and every platform whose probe cannot answer yet, therefore state no
  identity, which reduces the guard to the per-build key.
- Each platform reports different material, and one Cargo invocation builds one target, so a host
  states the value that its target reports. The variable does not name a platform, so a value meant
  for another target reaches the key derivation silently. Absent material fails the start, and wrong
  material cannot, because the build-time value never reaches the running process.
- Expansion costs size and time. See [budgets](../plan/07-state-and-budgets.md).
- Fidelity ships a macro crate. See [delivery](../plan/06-delivery.md).
