# ADR-0009: Complete initial actions before start returns

- Status: accepted
- Date: 2026-08-20

## Decision

`start()` returns only after the worker completes every action from the initial scan. A `Deny`
latch is active before success. A `Callback` completes before success. A `Crash` stops the process,
so `start()` does not return.

The callback receives `&Handle` and `&Finding`. The runtime builds the handle before the worker can
call host code. The callback still runs on the worker thread.

A host callback can extend the duration of `start()`. Detector cost measurements exclude host
callback time. An early worker stop returns `StartError::WorkerStoppedDuringStart`.

This decision supersedes the initial action boundary in
[ADR-0005](0005-library-owned-runtime.md). That ADR still owns the runtime lifetime and ownership.
The [runtime plan](../plan/03-runtime-and-api.md) holds the operational sequence.

## Why

A return before the action creates a gap between detection and the selected response. The first
host operation can run before a callback, and code after `start()` can run before a crash.

The handle lets a callback read the authoritative state or add a host denial. The worker owns the
callback thread, so the host receives this access without a second callback path.

## Consequences

- A callback should return quickly, because the initial callback extends `start()`.
- The worker reports readiness only after it applies all initial actions.
- A failed readiness report releases the process-wide runtime slot.
- Tests run `Crash` controls in a child process.
