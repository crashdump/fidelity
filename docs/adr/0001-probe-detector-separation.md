# ADR-0001: Separate platform probes from detectors

- Status: accepted
- Date: 2026-08-07

## Decision

Platform probe crates return narrow observations from operating-system interfaces. Built-in
detectors interpret those observations into category, strength, and typed evidence. Policy and
actions remain in `fidelity-engine`.

`fidelity-core` holds the trait between the two sides. Probes implement it and detectors consume it,
so neither imports the other. Probe code does not choose a response, calculate a score, or hide an
OS error as a clean result. Platform `unsafe` is confined to probe boundaries.

## Why

OS access needs target-specific testing and careful `unsafe` review. Interpretation and policy need
deterministic cross-platform tests. Separating them makes both testable and keeps platform APIs out
of the stable facade. A trait, rather than a fact struct, lets a detector pull only what it needs.
Detectors run at different cadences, so eager collection would run expensive probes far too often.

## Consequences

- Cargo enforces the separation. A dependency cycle is a build error, not a review finding.
- Detector logic for any target compiles and tests on an ordinary CI runner.
- Capability and health failures are explicit probe outcomes.
- A new fact is a breaking change for every probe crate at once, unless the trait method has a
  default that returns `Unsupported`.
- A detector still requires a real hostile backend test before release.
