//! Reports how soon the worker scans after the machine resumes this process.
//!
//! A mobile system suspends an application and resumes it later, and
//! `docs/plan/03-runtime-and-api.md` makes a full scan the worker's first work
//! item after that resume. An attacker that acts while the application sleeps
//! must not hold a window afterwards, so the delay between the resume and the
//! first scan is the time that a host is exposed for.
//!
//! The example needs no attacker, because it measures the worker rather than a
//! detector. The runtime already stamps a slot on every scan that reports a
//! finding, so the newest stamp is the time of the most recent scan.
//!
//! To carry a stamp on every system, the example pins an identity that this
//! image cannot hold: a digest of zero bytes, a team that Apple never issued,
//! and a requirement that names an absent identifier. The identity detector
//! then reports on every scan, on every platform, and the example needs no
//! emulator and no unsigned build to produce one. The finding is the clock, and
//! the example reads no other part of it.
//!
//! Both clocks belong to this process, which is why the subject measures itself
//! rather than the script that freezes it. The poll loop below sleeps as the
//! worker does, so it runs again at the same moment, and the resume is the
//! first poll that follows a long gap.
//!
//! ```text
//! cargo run --example resume &
//! kill -STOP <pid>; sleep 20; kill -CONT <pid>
//! ```
//!
//! The example exits with a success code when the first scan after the resume
//! lands inside the budget, and with a failure code when it does not.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fidelity::{
    AuthenticodeThumbprint, CertificateSha256, Choice, CodeRequirement, ContentDigest,
    DetectorState, ExpectedIdentity, Handle, TeamIdentifier,
};

/// How often to read the state.
const POLL: Duration = Duration::from_millis(200);

/// The gap in the poll loop that states that the machine froze this process.
///
/// The control freezes this process for 20 seconds, and the poll above is
/// 200 ms, so this sits far from both. It was 3 s until 2026-08-20. A loaded
/// machine can starve a thread for seconds, and a stall that this loop read as
/// a freeze would measure a resume that never happened, which reads exactly
/// like a worker that waited. Ten seconds is still half the freeze.
const FROZEN: Duration = Duration::from_secs(10);

/// How long to wait for the worker's own first scan.
///
/// The worker cycles every 5 seconds plus jitter, so one cycle always lands
/// inside this.
const SETTLE: Duration = Duration::from_secs(30);

/// How long to wait for a freeze that never arrives.
const DEADLINE: Duration = Duration::from_secs(90);

/// How long to wait for the first scan once the process runs again.
const AFTER: Duration = Duration::from_secs(20);

/// How late the first scan after a resume may be, in milliseconds.
///
/// The worker cycles every 5 seconds, plus jitter, so a worker that waited a
/// whole fresh cycle lands far outside this. The budget separates the two
/// answers and it does not grade the faster one.
const BUDGET_MS: i64 = 1_500;

/// How far before the resume a scan may carry its stamp and still count.
///
/// The worker and the poll loop run again at the same moment, so the worker may
/// stamp its scan a few milliseconds before this thread reads the clock. A scan
/// from before the freeze is tens of seconds older, so it never reaches this,
/// and the example cannot read one of those as the first scan after the resume.
const TOLERANCE_MS: i64 = 1_000;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let handle = fidelity::new().expected_identity(unmatchable()?).start()?;

    println!("pid {}", std::process::id());
    let Some(before) = newest_scan(&handle) else {
        println!("the pinned identity reached no detector here, so no scan carries a stamp");
        println!("the example measures the worker with that stamp, and it proves nothing here");
        std::process::exit(2);
    };
    println!("start: the newest scan carries the stamp {before}");

    // Wait for the worker to finish one scan of its own before asking for the
    // freeze. `start()` returns as soon as its synchronous scan ends, and the
    // worker then begins its first cycle, so a freeze here can land inside
    // that scan. A scan stamps its slot with the time it started, so a scan
    // that the machine froze in the middle carries a stamp from before the
    // freeze, and the rule below reads it as older than the resume and waits
    // for the cycle after it.
    //
    // That is what the macOS arm measured on 2026-08-20: it reported 6649 ms,
    // which is one cycle. The window is the first `code_identity`, which costs
    // 9.5 ms on macOS and 7.0 us on iOS, and only macOS ever failed. The wait
    // below also states the case that the promise is about, which is a worker
    // that the machine suspends between two scans.
    let Some(settled) = settle(&handle, before) else {
        println!(
            "the worker ran no scan of its own within {} seconds",
            SETTLE.as_secs()
        );
        std::process::exit(2);
    };
    println!("the worker finished a scan of its own, at {settled}");
    println!("freeze this process now, hold it, then continue it");

    // The worker and this loop both sleep, so both run again when the machine
    // continues the process. A poll that follows a long gap is therefore the
    // resume, and it is the first moment that this process can read a clock.
    //
    // Every poll before the freeze keeps `seen` current, and that is what makes
    // the measurement below safe. A read taken after the resume would race the
    // worker: the worker may stamp its first scan before this thread runs, and
    // the example would then wait for the cycle after it and report that.
    let began = Instant::now();
    let mut last = Instant::now();
    let mut seen = settled;
    while began.elapsed() < DEADLINE {
        std::thread::sleep(POLL);
        let gap = last.elapsed();
        last = Instant::now();
        if gap < FROZEN {
            if let Some(scan) = newest_scan(&handle) {
                seen = scan;
            }
            continue;
        }

        let resumed = unix_ms();
        println!(
            "the machine froze this process for {:.1}s",
            gap.as_secs_f32()
        );
        println!("the last scan before the freeze carries the stamp {seen}");
        report(&handle, resumed);
        return Ok(());
    }

    println!("no freeze within {} seconds", DEADLINE.as_secs());
    std::process::exit(1);
}

/// Waits for the first scan after the resume, and reports its delay.
///
/// The function returns only when the delay is inside the budget. Every other
/// route leaves the process, because a control states one answer.
fn report(handle: &Handle, resumed: u64) {
    let began = Instant::now();
    let at = i64::try_from(resumed).unwrap_or(0);
    while began.elapsed() < AFTER {
        if let Some(scan) = newest_scan(handle) {
            // A delay of zero or less is the worker stamping its scan before
            // this thread read the clock, and it states the same thing. The
            // tolerance is what keeps a scan from before the freeze out.
            let delay = i64::try_from(scan).unwrap_or(i64::MAX) - at;
            if delay >= -TOLERANCE_MS {
                // The last line carries the number, because the harness keeps
                // that line and nothing else. A row that stated only the
                // verdict cost an hour on 2026-08-20, when a run failed here
                // and the record held no measurement to read.
                if delay <= BUDGET_MS {
                    println!(
                        "a full scan is the worker's first work item after a resume, {delay} ms"
                    );
                    return;
                }
                println!("the worker waited {delay} ms, and the budget is {BUDGET_MS} ms");
                std::process::exit(1);
            }
        }
        std::thread::sleep(POLL);
    }

    println!("no scan within {} seconds of the resume", AFTER.as_secs());
    std::process::exit(1);
}

/// Waits for the worker to stamp a scan of its own, and answers when it did.
///
/// The stamp that `start()` left comes from its synchronous scan, on the
/// caller's thread. A newer one can only come from the worker, so it proves
/// that the worker reached its wait rather than its first scan.
fn settle(handle: &Handle, before: u64) -> Option<u64> {
    let began = Instant::now();
    while began.elapsed() < SETTLE {
        match newest_scan(handle) {
            Some(scan) if scan > before => return Some(scan),
            _ => std::thread::sleep(POLL),
        }
    }
    None
}

/// An expected identity that no image on any platform holds.
///
/// The example needs a detector that reports on every scan, because that is
/// what stamps the time of a scan. An identity that cannot match gives one on
/// every platform, so the measurement below needs no emulator and no unsigned
/// build. A digest of zero bytes is the value for the three platforms that
/// compare a digest, and Apple issues no team of ten letter As.
fn unmatchable() -> Result<ExpectedIdentity, Box<dyn std::error::Error>> {
    const ZERO: [u8; 32] = [0; 32];

    Ok(ExpectedIdentity::new()
        .windows(Choice::Value(AuthenticodeThumbprint::from_bytes(ZERO)))
        .android(Choice::Value(CertificateSha256::from_bytes(ZERO)))
        .linux(Choice::Value(ContentDigest::new(ZERO)?))
        .ios(Choice::Value(TeamIdentifier::new("AAAAAAAAAA")?))
        .macos(Choice::Value(CodeRequirement::new(
            "identifier \"fidelity.resume.control.absent\"",
        )?)))
}

/// When the most recent scan that reported a finding ran.
///
/// A detector stamps its slot every time it reports, so the newest stamp
/// across every slot is the time of the most recent scan. A system where the
/// pinned identity above reaches no detector carries no stamp, and this
/// answers `None` there.
fn newest_scan(handle: &Handle) -> Option<u64> {
    handle
        .snapshot()
        .detectors()
        .iter()
        .filter_map(DetectorState::latest)
        .max()
}

/// The wall-clock time, in milliseconds since the Unix epoch.
fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}
