//! Reports whether the worker notices code that arrives after start.
//!
//! The runtime baseline is the one signal that works on every platform. An
//! absolute rule cannot separate injected code from the shared cache on Apple,
//! so a change against the start of the process is what remains.
//!
//! The example only observes. It holds no hostile code, because the workspace
//! forbids `unsafe` outside a probe crate, and an example that mapped its own
//! memory would prove the detector against itself. The control is external,
//! and it is the shape a real injection takes: an agent that is already in the
//! process maps executable memory once the application is running.
//!
//! ```text
//! cargo run --example late                              # clean control
//! DYLD_INSERT_LIBRARIES=./delayed.dylib ... --example late   # macOS
//! LD_PRELOAD=./delayed.so ...            --example late      # Linux
//! inject-windows.exe <pid>                                   # Windows
//! ```
//!
//! Windows offers no preload variable, so the control there maps the memory
//! from outside. The example prints its process identifier for that reason,
//! and it prints it after `start()` captured the baseline, so a driver that
//! waits for the line also waits for the baseline.
//!
//! The example exits with a success code when the worker reports the change,
//! and with a failure code when the deadline passes first.

use std::time::{Duration, Instant};

use fidelity::{Handle, Outcome};

/// How long to wait for the worker to notice.
const DEADLINE: Duration = Duration::from_secs(40);

/// How often to read the latched state.
const POLL: Duration = Duration::from_millis(250);

/// The detector that this example watches.
const BASELINE: &str = "integrity.runtime_baseline";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The example watches the detector rather than the denial latch. An
    // ad-hoc build fails platform trust at `Medium` on every clean run, so a
    // latch on the whole `Integrity` category would report that instead of
    // this. The default action stays `Report`, and nothing else interferes.
    let handle = fidelity::new().start()?;

    println!("pid {}", std::process::id());
    println!("start: {}", baseline(&handle));
    if found(&handle) {
        println!("this build reports a change at start, so it proves nothing here");
        std::process::exit(2);
    }

    let began = Instant::now();
    while began.elapsed() < DEADLINE {
        if found(&handle) {
            println!(
                "caught after {:.1}s: {}",
                began.elapsed().as_secs_f32(),
                baseline(&handle)
            );
            return Ok(());
        }
        std::thread::sleep(POLL);
    }

    println!(
        "after {} seconds: {}",
        DEADLINE.as_secs(),
        baseline(&handle)
    );
    println!("no code arrived after start");
    std::process::exit(1);
}

/// Reports whether the baseline detector holds a finding now.
fn found(handle: &Handle) -> bool {
    handle.snapshot().detectors().iter().any(|state| {
        state.detector().name() == BASELINE && matches!(state.outcome(), Outcome::Finding(_))
    })
}

/// Describes what the baseline detector reports now.
fn baseline(handle: &Handle) -> String {
    for state in handle.snapshot().detectors() {
        if state.detector().name() != BASELINE {
            continue;
        }
        return match state.outcome() {
            Outcome::NotRun => "no scan reached the baseline detector".to_owned(),
            Outcome::Clean => "no code arrived after start".to_owned(),
            Outcome::Unsupported { reason } => format!("baseline unsupported, {reason}"),
            Outcome::Finding(finding) => {
                format!("{:?}, {:?}", finding.strength(), finding.evidence())
            }
        };
    }
    "the baseline detector is absent from this build".to_owned()
}
