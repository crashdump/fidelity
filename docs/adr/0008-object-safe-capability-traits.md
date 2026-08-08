# ADR-0008: Keep every capability trait object safe

- Status: accepted
- Date: 2026-08-09

## Decision

The engine holds one environment as `Box<dyn Environment>`. Every capability trait therefore stays
object safe: no generic method, no method that returns `Self`, and no `async fn`. A capability
method takes `&self` and returns an owned fact.

A detector takes the narrow capability that it reads, as a generic bound with `?Sized`, and not the
whole environment. That call is a static dispatch, and `&dyn Environment` still satisfies it,
because `Environment` inherits every capability trait.

## Why

The Rust guidance in `.agents/skills/` is "static where you can, dynamic where you must". Two
different call sites reach opposite answers.

A detector runs on one narrow capability, and its signature should state what it reads. A generic
bound does both, so detectors use static dispatch.

The engine holds the environment for the life of the process and calls it once per scan. A type
parameter there would spread through the worker, the runtime, and the start sequence, and it would
make the platform seam return a different type in each branch. Monomorphization would buy nothing
measurable, because a scan runs every few seconds and one build holds one environment type.

Object safety is the price, and it is small. A capability answers a question, so it returns an owned
`Observation` of a fact. None of the eight planned capabilities needs a generic method.

## Consequences

- A new capability method must take `&self` and return an owned value. A method that wants to return
  `impl Iterator` returns a `Vec` instead.
- The compiler enforces this. `Box<dyn Environment>` fails to build when a trait stops being object
  safe, so no test is needed.
- Fidelity must not adopt `async` in the probe surface without superseding this decision.
- The trait family may grow without a change to the engine, because the engine names one type.
