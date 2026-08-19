# ADR-0006: Make responses explicit and configurable

- Status: accepted
- Date: 2026-08-07

## Decision

Each category has exactly one action. The host selects it. Actions do not compose,
and the project ships no presets and no policy language. Every finding is published, including a
finding below the action threshold.

The [response contract](../plan/01-product.md#v1-responses) holds the operational detail.

## Why

Applications have different availability and security needs. A report-only library cannot prevent
anything locally. A mandatory fail-closed response would be unsafe for many hosts. Four clear
actions cover v1, and a callback covers the rest.

## Consequences

- The category is the configuration boundary. There is no per-detector public policy.
- `Deny` is cooperative. The host must place `ensure_allowed()` at every protected operation.
- A lower threshold is an explicit choice. It accepts weaker evidence and more false positives.
- A callback covers a custom or multi-step response, and the
  [response contract](../plan/01-product.md#v1-responses) holds how a host latches its own verdict.
