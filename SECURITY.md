# Security policy

Fidelity is before its first release. Code runs on four platforms, and no platform is supported
yet, because a supported label needs the full release tests. The
[test record](tests/platform/README.md) states what each platform proved and what it did not, and
the
[gaps](tests/platform/README.md#gaps) are the work list. Read it before you report, because a limit
that
the record already names is a limit and not a defect.

## What to report

A defect in Fidelity itself. Examples:

- a detector that reports `Clean` when the condition it checks is present;
- a bypass that is cheaper than the strength assigned to a detector claims;
- memory growth, a deadlock, or a crash that an attacker can trigger;
- an unsafe wrapper that breaks its documented invariant; or
- any remote network path, which [ADR-0004](docs/adr/0004-no-network-in-library.md) forbids.

## What is not a vulnerability

These are documented limits. See the [security model](docs/plan/02-security-model.md).

- An attacker who runs code in the same process patches a detector, rewrites state, forges or
  suppresses a report, or bypasses `ensure_allowed()`.
- Root, an administrator, a kernel compromise, or a hypervisor defeats a check.
- A host that never calls `ensure_allowed()` is not protected by `Deny`.
- A report is unauthenticated. Every report is unauthenticated by design.

Report a bypass that is cheaper than a detector's assigned strength. The strength is the claim.

## How to report

Email <ap@cdfr.net>. Do not open a public issue for an unfixed defect.

Include the platform and OS version, the detector, what you expected, what happened, and a
reproduction. Expect an acknowledgement within 7 days.

We will agree a disclosure date with you. Please give us 90 days before public disclosure, or less
if the defect is already public or being exploited.
