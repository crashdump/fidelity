# Commercial vendor survey

Surveyed 2026-08-08: Guardsquare DexGuard and iXGuard, Promon SHIELD, Appdome, Digital.ai. The
capability rows come from vendor documentation and are unverified.

## How they are built

Every leading product is **build-time or post-compile**, not a linked library.

- DexGuard and iXGuard are compiler-based. Guardsquare states they "automatically inject endless
  variations of integrity checks" into existing code, with polymorphic obfuscation so "no two
  protected builds ever look the same".
- Promon SHIELD and Appdome inject post-compile, with no source change.

This is the central structural difference, and it produces the critique below.

## The critique of library-form protection

Guardsquare argues against SDK-based protection on two properties of the shape: library logic is
separate from application code at the package and the function level, so the interface is a target,
and one build protects every consumer, so one bypass works everywhere. Open source lowers the cost
of writing that bypass. The argument applies to Fidelity, which is why the
[security model](../plan/02-security-model.md#attackers) states both properties as its own and
[ADR-0007](../adr/0007-value-producing-check.md) answers them.

## Capability comparison

| Capability | Vendors | Fidelity |
|---|---|---|
| Root, jailbreak, debugger, hooking, emulator, tamper | all | v1 |
| Repackaging | all | v1, through expected identity |
| Overlay, accessibility abuse, screen capture, keylogger | all | v1, in `UiAbuse` |
| Obfuscation, control-flow flattening, string encryption | all | out of scope; a library cannot rewrite its host |
| White-box cryptography | Promon | out of scope |
| Network, MITM, certificate pinning | Appdome, others | out of scope, [ADR-0004](../adr/0004-no-network-in-library.md) |
| Telemetry to a SIEM or fraud platform | all, central to their model | out of scope; the host exports if it wants to |
| Application binding, where removal breaks the app | Promon ships this | deferred |

## Adopted

- The check must be load-bearing, not advisory. [ADR-0007](../adr/0007-value-producing-check.md).
- A performance budget is a product constraint. Vendors compete on overhead.
- UI-layer attacks belong in v1. Every vendor ships them. They map to MASVS-PLATFORM, not
  MASVS-RESILIENCE.
- The form factor is open. Vendor advantage comes from controlling the whole binary. A build-time
  component beside the library is in scope if the requirements need one.

## Rejected

- Obfuscation. A library cannot rewrite its host. Use a compiler-based tool alongside Fidelity.
- Telemetry. [ADR-0004](../adr/0004-no-network-in-library.md).
- Compliance claims.
- Named-tool detection as strong evidence. Vendors advertise Magisk, KernelSU, Checkra1n, Frida, and
  Burp by name. A name stays supporting evidence.
- Self-heal and restore. Rewriting executable memory needs a write-execute violation, and an
  attacker who can patch code can patch the restorer.
