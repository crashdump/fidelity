# ADR-0003: Keep the detector set closed

- Status: accepted
- Date: 2026-08-07

## Decision

v1 detectors are built into Fidelity and composed at compile time. The supported facade exposes no
custom detector trait, runtime plugin loading, or detector registration.

## Why

A plugin loads arbitrary in-process code, and Fidelity must then trust it. That conflicts with an
instrumentation and injection detector. A closed set also bounds retained state, makes strength
assignments reviewable, and lets Fidelity own cross-platform semantics and verification.

## Consequences

- Categories are the configuration boundary; there is no per-detector public policy.
- `fidelity-testkit` may inject observations into isolated core runtimes for tests without becoming
  a production extension mechanism.
- A new detector requires a Fidelity release, and the same clean and hostile controls as the others.
