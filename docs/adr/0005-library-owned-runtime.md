# ADR-0005: Own one explicit runtime per process

- Status: accepted
- Date: 2026-08-07

## Decision

The supported facade permits one active runtime per process. Fidelity owns the worker. The host does
not supply a runtime, and the host does not set a scan interval. Configuration is immutable after
`start()`. The runtime then runs until the process stops, and the host cannot stop it.

The [lifecycle](../plan/03-runtime-and-api.md#lifecycle) holds the operational detail.

## Why

Two production engines would duplicate expensive OS work and create contradictory process policy. A
library-owned worker gives every host the same lifecycle, and it does not force an async runtime on
the host. An explicit start call avoids loader-lock and static-initializer hazards. A public stop
would put an off-switch in a security library, and a handle that owned the runtime would end
detection when a scope exits.

## Consequences

- The engine carries no Tokio dependency.
- Protection cannot be turned off through the API. A dropped handle changes nothing.
- The `Deny` latch lives in the facade, which is the layer that holds the single-runtime rule.
- A mobile scan follows the application lifecycle. Fidelity needs no background service and no
  special entitlement.
- Deterministic tests need a separate path. Engine and testkit code may create isolated runtimes.
