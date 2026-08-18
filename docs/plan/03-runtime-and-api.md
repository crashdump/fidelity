# Runtime and API

## Lifecycle

`fidelity::new()` returns a builder. `start(self)` consumes the builder, so the configuration
cannot change afterwards. `start(self)`:

1. claims the single process-wide runtime slot;
2. validates the configuration;
3. constructs the applicable platform backend;
4. completes an initial scan; and
5. starts the library-owned worker before it returns `Handle`.

The initial scan records findings and latches state. It does not apply an action. `start()` returns
the handle first. The worker then applies every qualifying action from the initial scan as its first
work item. A `Crash` from the initial scan therefore stops the process immediately after `start()`
returns. A `Deny` latch is active as soon as `start()` returns, so the first `ensure_allowed()` call
can fail.

The initial scan runs only the detectors whose probes are bounded and cheap: image identity, the
runtime baseline, and tracer state. Root, jailbreak, emulator, UI, and loopback detectors run on the
worker's first cycle, because they cost too much on the caller's thread. The latch at `start()`
therefore covers the synchronous set only.

A second `start()` returns `StartError::AlreadyRunning`. The handle is cloneable, and clones refer
to the same runtime and state. The runtime then runs until the process stops. There is no public way
to stop it, and a dropped handle changes nothing. The configuration is therefore fixed for the life
of the process. Engine and testkit internals may create isolated runtimes for deterministic tests.

There is no public scan-interval setting. Each backend uses internal frequent, periodic, and
lifecycle-triggered work with jitter. Desktop workers run continuously. Mobile workers pause when
the OS suspends the application. On resume, a full scan is the worker's first work item. Fidelity
needs no background service and no special entitlement.

## Configuration

Each category has one setter that takes its action and its `SignalStrength` threshold together, and
the defaults are `Action::Report` and `SignalStrength::High`. The setters are `integrity()`,
`debugging()`, `instrumentation()`, `device_compromise()`, `virtualization()`, and `ui_abuse()`.

`expected_identity(ExpectedIdentity)` supplies the optional per-platform identity values. One call
covers every target, so the configuration cross-compiles. See the
[image identity tiers](04-detectors-and-platforms.md#image-identity-tiers).

Android needs the virtual machine for its Java APIs, and the probe finds it, so the host supplies
nothing and the configuration gains no Android-only field. See
[delivery](06-delivery.md#engineering-constraints).

`deny_until_first_full_scan()` denies until the worker completes its first full cycle. It closes
the startup window in the [security model](02-security-model.md#deny-is-cooperative), and it is off
by default, because an early call then denies the host's own startup path.

The builder surface is:

```rust
use fidelity::{Action, SignalStrength};

let _handle = fidelity::new()
    .integrity(Action::Crash, SignalStrength::High)
    .instrumentation(Action::Callback, SignalStrength::Medium)
    .on_finding(|finding| {
        // Keep this fast: it runs on the Fidelity worker.
        eprintln!("{finding:?}");
    })
    .start()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

### Callbacks

`Callback` needs `on_finding()` at start, and a missing callback is a start error. One callback
serves every category that selects `Callback`, and the finding names the category. It runs for a
finding at or above that category's threshold, and never for a category with another action.

The callback runs synchronously on the worker, after the runtime latches the state. It never runs on
the calling thread, including the thread that called `start()`. It must be quick, because it delays
later scans. `ensure_allowed()` and `snapshot()` are safe inside the callback, because the runtime
holds no lock while the callback runs.

A panic in the callback must not stop detection. The runtime catches the unwind. It records a `Low`
detector-health finding in the category of the finding that the callback received. The worker
continues. Under `panic = "abort"` the process stops instead, because the host selected that
strategy.

## Handle and error contract

- `fidelity::new() -> Builder`, and `Builder::start(self) -> Result<Handle, StartError>`.
- `Handle::ensure_allowed() -> Result<(), Denied>` reads the already-latched decision, and it
  allocates nothing. `Denied` keeps its fields private and exposes `categories()` and `reason()`.
  `DenialReason` separates a latch from absent coverage, and it is `#[non_exhaustive]`. This check
  is advisory. See [guarded constants](#guarded-constants) for the structural path.
- `Handle::deny(Category)` latches a denial on the host's own judgment, because Fidelity never adds
  weak signals together itself. It only adds a denial, so it is not an off-switch. A host latch has
  no finding behind it, so `snapshot()` keeps it separate.
- `StartError::AlreadyRunning` identifies the process-wide singleton conflict. A missing callback, a
  platform initialization failure, a worker creation failure, and every other fundamental startup
  failure is a distinct typed case. Fidelity does not flatten them into an unstructured string. A
  failed `start()` releases the slot, so one bad configuration never blocks a corrected retry.
- `snapshot()` returns the authoritative bounded state: the permanent latch, the categories that
  the host latched, and the retained detector state. See
  [state and budgets](07-state-and-budgets.md).

## Guarded constants

`ensure_allowed()` is one branch, and an attacker finds every call site by searching for one symbol.
`guarded!()` removes the branch. The host wraps a critical literal:

```rust
let host = fidelity::guarded!(&handle, "api.example.com");  // Secret<15>, derefs to &str
```

The macro expands to inline decryption at the call site, and each constant gets its own key schedule
from the build seed and the literal. A shared reader would let one hook dump every constant, so
there is none. A wrong key yields a wrong value, never an error, so nothing is left to invert.

The build states its identity choice, and the running image must supply it.
`FIDELITY_CODE_IDENTITY` carries the identity that the operating system reports for the signed
application, or the word `none`. A build that names an identity fails `start()` on an image that
reports none, and the error is `StartError::IdentityBindingUnavailable`. Without that check the
host reads a wrong value from every guarded constant, and nothing reports it. An unsigned image, an
image signed ad hoc, and a platform whose probe cannot answer all reach it, so a local build states
`none`.

Each platform reports different material, and every platform reports it as text. The variable
carries a string, and the expansion takes the bytes of that string, so a probe whose material is
not text makes a bound build impossible on its platform. Apple reports the team identifier, which
is already text. Android reports the signing certificate digest as lowercase hexadecimal, which is
the form that `keytool` and `apksigner` print.

One Cargo invocation builds one target, so a host states the value that its target reports, and a
second target is a second invocation with its own value. The value names the kind of material
before it states the material, as in `apple:ABCDE12345`. A kind that the target does not report
fails the build, and so does a digest that is not 64 lowercase hexadecimal digits. Both would
otherwise send the key derivation material that the running image never reports. Absent material
fails the start. Wrong material of the right kind cannot, because the build-time value never
reaches the running process.

To keep that promise, the stream stays inside the alphabet of the value: a guarded literal holds
printable ASCII, and every key, right or wrong, gives printable ASCII back. Byte encryption would
give invalid UTF-8, and that decode failure is an oracle. A guarded value must also be 8 bytes or
longer. Both rules fail the build, not the run.

`Secret<N>` derefs to the wrapped type and wipes its buffer on drop, so a plaintext lives for one
scope. A read decrypts every time, costs about 700 ns, and needs a `Handle`.
[ADR-0007](../adr/0007-value-producing-check.md) holds the key derivation and its limits.

## Action ordering

For each observation, the runtime:

1. records the outcome in the detector state, which retains the strongest finding;
2. latches the permanent category denial, if the host selected `Deny` and the finding is at
   threshold; and
3. applies the qualifying callback or stops the process.

The denial latch is the only latch, so a `Report` finding denies nothing. Steps 1 and 2 finish
inside the initial scan, and step 3 belongs to the worker. A `Deny` is therefore active as soon as
`start()` returns, and `start()` still returns before a callback runs.

`Crash` does not unwind or run cleanup, and it never fires on a
[health finding](01-product.md#v1-responses). Its finding is authoritative state, and the callback
may never run.

Finding contents, retention, and the budgets are in [state and budgets](07-state-and-budgets.md).

## Diagnostics and network boundary

Internal diagnostics use `tracing`, behind an optional feature that is off by default, and Fidelity
never installs a subscriber. The feature is off so that a default build resolves to no external
crate, which [delivery](06-delivery.md#engineering-constraints) states and a test holds. A host that
wants the events turns the feature on and installs a subscriber of its own.

The engine reports every event, because the engine owns the runtime work. An event names the
detector, the category, the strength, and the action. A diagnostic message must not contain a secret
or raw application data, because the host's subscriber writes it wherever that host sends its logs.

No crate may contain a remote networking client. A detector may run a documented loopback-only
probe, such as a query to a local instrumentation endpoint. The probe must be bounded, must not
leave the device, and must degrade to a health finding on failure.
