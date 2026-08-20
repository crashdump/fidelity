# Security model

## Protected boundary

Fidelity runs inside the application process and observes that process and its local execution
environment. It may make local OS queries and local loopback probes. It sends nothing to a remote
system and has no independent trust anchor.

The host application still protects its data, places `ensure_allowed()` at meaningful operation
boundaries, chooses policy, and validates its complete shipped package.

## Attackers

Fidelity raises the cost of:

- commodity debuggers, tracers, hook frameworks, and injectors;
- common root and jailbreak tools, and a repackaged application;
- altered code, signatures, mappings, imports, and runtime dispatch; and
- analysis environments that expose usable local evidence.

Fidelity can sometimes observe a stronger attacker. It cannot reliably defeat an administrator,
root, a kernel compromise, a hypervisor that emulates the target perfectly, or code that runs inside
the same process. An in-process attacker can patch a detector, suspend the worker, rewrite the
state, forge or suppress a finding, and bypass a host-side check.

Two properties make that attacker's work cheap. Fidelity is a separate unit in the host package,
with a visible interface, so the boundary itself is a target. One build protects every consumer, and
the source is public, so one bypass works everywhere.
[Guarded constants](../adr/0007-value-producing-check.md) raise the cost of both: they remove the
branch, and a per-build key makes each application differ.

## Security properties

Detection and local response hold to these invariants:

- A finding is permanent history. A recovery can make a detector healthy again, but it does not
  remove the finding and it does not clear the category latch.
- The strongest finding for a detector and a category never decreases.
- Fidelity never converts a detector error into a clean result.
- An unsupported capability creates metadata. It creates no finding and no action.
- The runtime latches the enforcement state before it runs a callback.
- The runtime holds no lock while a callback runs, so the callback can read the state safely.

Findings are unauthenticated. Applications must not treat them as evidence against an attacker who
controls the process.

## False-positive policy

Every category defaults to `Report` with a `High` action threshold. An application may lower a
category threshold, or select a stronger response, when its risk appetite justifies the effect on
availability.

A detector failure is a detailed `Low`-strength health finding. At the default threshold, Fidelity
reports it but takes no stronger action. To lower a category threshold to `Low` is the explicit
fail-closed choice. Repeated failures never accumulate into a stronger signal.

A `Low` threshold makes a detector failure reach the configured action, and an attacker who can
break one detector controls that failure. `Deny` at `Low` therefore gives an attacker a way to stop
the host's protected operations. `Crash` at `Low` would give an attacker a way to stop the process,
so [`Crash` never fires on a health finding](01-product.md#v1-responses).

A detector must not carry `High` because several weak heuristics agree. The semantics of the
individual mechanism and its measured false-positive behavior must justify each strength.

## `Deny` is cooperative

The latch lives in the `fidelity` facade, the single-runtime layer. `fidelity-engine` keeps denial
per runtime, so isolated test runtimes stay independent.

`Deny` latches globally and permanently, but the host must call `ensure_allowed()` immediately
before each protected operation. The method is a cheap read of already-latched state. It is not a
fresh scan, an authorization system, or an atomic boundary around the operation. A check-then-use
race therefore remains possible. The resume scan opens a second window: Fidelity latches a change
that starts during suspension only when that scan completes. A measurement bounds that window: the
first scan after a resume landed 0 to 1 ms after it, on all four arms that
[the record](../../tests/platform/README.md#the-resume-promise) holds. Startup opens a third
window: the expensive detectors run after `start()` returns, so an early call sees the synchronous
set only. `deny_until_first_full_scan()` closes the third window at the cost of availability.

The permanent latch has no authenticated exception, because Fidelity holds no trust anchor. A
secret that unlocks the latch ships inside the binary that the attacker already controls. The
recovery path is a restart under a different configuration, and the host owns that decision.
