# ADR-0002: Use signal strength without scoring

- Status: accepted
- Date: 2026-08-07

## Decision

Fidelity uses three ordered strengths. It does not aggregate, weight, score, decay, or escalate
findings. Policy compares one finding against one category threshold.

The [signal model](../plan/04-detectors-and-platforms.md#signal-model) holds the operational detail.

## Why

A numeric score claims a precision that platform heuristics do not have. Correlated weak signals
that add up create false confidence, and they make the response hard to audit. Three ordered
strengths are enough for v1 risk choices, and the project can justify each one per mechanism.

## Consequences

- Every strength assignment needs clean and hostile controls.
- Repetition never turns an inconclusive detector into a compromise finding.
- Impact and application sensitivity stay host concerns. They are not detector fields. A host that
  wants to weigh several findings together does so in its callback, and latches the result with
  `Handle::deny()`. The judgment then carries the host's name, not Fidelity's.
- A difficult detector does not get a higher strength. It gets better evidence or it waits.
