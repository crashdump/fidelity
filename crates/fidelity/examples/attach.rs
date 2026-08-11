//! Proves that the worker notices a tracer that attaches after start.
//!
//! The other examples start under a debugger, so they show the initial scan
//! doing its work. The realistic case is different: the application is already
//! running, and an attacker attaches to it. Only the worker can catch that.
//!
//! Run the example, then attach to the process identifier that it prints:
//!
//! ```text
//! cargo build --example attach && ./target/debug/examples/attach &
//! ( echo continue; sleep 20 ) | lldb -p <pid>     # macOS
//! ( echo continue; sleep 20 ) | gdb -p <pid>      # Linux
//! ```
//!
//! The example exits with a success code when the worker catches the tracer,
//! and with a failure code when the deadline passes first, so a script can run
//! it as a check.

use std::time::{Duration, Instant};

use fidelity::{Action, Handle, Outcome, SignalStrength};

/// How long to wait for the worker to notice.
///
/// The internal cycle is a few seconds, plus jitter, so this leaves room for
/// several cycles on a loaded machine.
const DEADLINE: Duration = Duration::from_secs(30);

/// How often to read the latched state.
const POLL: Duration = Duration::from_millis(250);

/// The detector that this example watches.
const TRACER: &str = "debugging.tracer_present";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let handle = fidelity::new()
        .debugging(Action::Deny, SignalStrength::Medium)
        .start()?;

    println!("pid {}", std::process::id());
    println!("start: {}", tracer(&handle));
    if handle.ensure_allowed().is_err() {
        println!("a tracer held this process before start, so the worker proves nothing");
        std::process::exit(2);
    }
    println!("start: protected operation allowed");
    println!("attach a debugger now");

    let began = Instant::now();
    while began.elapsed() < DEADLINE {
        if handle.ensure_allowed().is_err() {
            let seconds = began.elapsed().as_secs_f32();
            println!("caught after {seconds:.1}s: {}", tracer(&handle));
            println!("protected operation denied");
            return Ok(());
        }
        std::thread::sleep(POLL);
    }

    println!("no tracer within {} seconds", DEADLINE.as_secs());
    std::process::exit(1);
}

/// Describes what the tracer detector reports now.
fn tracer(handle: &Handle) -> String {
    for state in handle.snapshot().detectors() {
        if state.detector().name() != TRACER {
            continue;
        }
        return match state.outcome() {
            Outcome::NotRun => "no scan reached the tracer detector".to_owned(),
            Outcome::Clean => "no tracer".to_owned(),
            Outcome::Unsupported { reason } => format!("tracer unsupported, {reason}"),
            Outcome::Finding(finding) => {
                format!("tracer found, {:?}", finding.strength())
            }
        };
    }
    "the tracer detector is absent from this build".to_owned()
}
