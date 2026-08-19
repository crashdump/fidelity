//! Reports whether the worker notices a redirected call target.
//!
//! A hook that rewrites one entry of the dispatch table redirects a call to
//! code that already exists. It maps no new executable region, so the runtime
//! baseline reports clean, and the table holds data rather than code, so no
//! executable-memory rule reaches it. Only a comparison of the table against
//! the start of the process reports it. That comparison is the
//! `instrumentation.dispatch_targets` detector, and this example watches it.
//!
//! The example only observes. It holds no hostile code, because the workspace
//! forbids `unsafe` outside a probe crate, and an example that rewrote its own
//! table would prove the detector against itself. The control is external, and
//! it is the shape a real hook takes: an agent that is already in the process
//! rewrites one dispatch target once the application is running.
//!
//! ```text
//! cargo run --example redirect                                # clean control
//! LD_PRELOAD=./hook.so FIDELITY_HOOK=inside ... redirect      # Linux hostile
//! ```
//!
//! The example exits with a success code when the worker reports the redirect,
//! and with a failure code when the deadline passes first.

use std::time::{Duration, Instant};

use fidelity::{Handle, Outcome};

/// How long to wait for the worker to notice.
const DEADLINE: Duration = Duration::from_secs(40);

/// How often to read the latched state.
const POLL: Duration = Duration::from_millis(250);

/// The detector that this example watches.
const DISPATCH: &str = "instrumentation.dispatch_targets";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The example watches the detector rather than the denial latch. An
    // ad-hoc or unsigned build reports on other categories on every clean run,
    // so a latch on a whole category would report that instead of this. The
    // default action stays `Report`, and nothing else interferes.
    let handle = fidelity::new().start()?;

    println!("pid {}", std::process::id());
    println!("start: {}", dispatch(&handle));
    if found(&handle) {
        println!("this build reports a redirect at start, so it proves nothing here");
        std::process::exit(2);
    }

    let began = Instant::now();
    while began.elapsed() < DEADLINE {
        if found(&handle) {
            println!(
                "caught after {:.1}s: {}",
                began.elapsed().as_secs_f32(),
                dispatch(&handle)
            );
            return Ok(());
        }
        std::thread::sleep(POLL);
    }

    println!(
        "after {} seconds: {}",
        DEADLINE.as_secs(),
        dispatch(&handle)
    );
    println!("no dispatch target moved after start");
    std::process::exit(1);
}

/// Reports whether the dispatch detector holds a finding now.
fn found(handle: &Handle) -> bool {
    handle.snapshot().detectors().iter().any(|state| {
        state.detector().name() == DISPATCH && matches!(state.outcome(), Outcome::Finding(_))
    })
}

/// Describes what the dispatch detector reports now.
fn dispatch(handle: &Handle) -> String {
    for state in handle.snapshot().detectors() {
        if state.detector().name() != DISPATCH {
            continue;
        }
        return match state.outcome() {
            Outcome::NotRun => "no scan reached the dispatch detector".to_owned(),
            Outcome::Clean => "no dispatch target moved after start".to_owned(),
            Outcome::Unsupported { reason } => format!("dispatch unsupported, {reason}"),
            Outcome::Finding(finding) => {
                format!("{:?}, {:?}", finding.strength(), finding.evidence())
            }
        };
    }
    "the dispatch detector is absent from this build".to_owned()
}
