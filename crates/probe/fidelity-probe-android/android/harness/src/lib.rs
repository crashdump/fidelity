//! The Android instrumented-test harness.
//!
//! An instrumented test runs inside an application process, so it supplies the
//! two things a plain test binary cannot: a real virtual machine, and a real
//! package that the package manager knows. This library exposes the probe to
//! that test.
//!
//! **The harness plays the host, and that is the point.** The probe defines no
//! `JNI_OnLoad`, because one shared library holds one such function and the
//! host owns it. This library is the shared library that the test application
//! loads, so it owns that function, captures the virtual machine, and hands the
//! address to the probe exactly as a real host does.
//!
//! It ships in no release. Only the Android library project loads it.

use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};
use std::hint::black_box;
use std::time::{Duration, Instant};

// The cost measurements read through `&dyn Environment`, so the capability
// traits that they call reach this file through the supertrait and not through
// a name of their own.
use fidelity_core::{Dispatch, Environment, Identity, Lifecycle, Observation, WorkerSetup};
use fidelity_probe_android::AndroidEnvironment;
use fidelity_types::{CertificateSha256, Choice, ExpectedIdentity};

/// The virtual machine that the runtime handed this library when it loaded.
static JAVA_VM: AtomicUsize = AtomicUsize::new(0);

/// The JNI version that this library asks for.
const JNI_VERSION_1_6: i32 = 0x0001_0006;

/// Captures the virtual machine, the way a host does.
///
/// The runtime calls this once, when the application loads the library.
#[unsafe(no_mangle)]
pub extern "system" fn JNI_OnLoad(vm: *mut c_void, _reserved: *mut c_void) -> i32 {
    JAVA_VM.store(vm as usize, Ordering::Release);
    JNI_VERSION_1_6
}

/// Reports that the library loaded and the symbol resolved.
#[unsafe(no_mangle)]
pub extern "system" fn Java_fidelity_probe_Harness_smoke(
    _env: *mut c_void,
    _class: *mut c_void,
) -> i32 {
    42
}

/// Reports whether the runtime handed this library a virtual machine.
#[unsafe(no_mangle)]
pub extern "system" fn Java_fidelity_probe_Harness_hasVirtualMachine(
    _env: *mut c_void,
    _class: *mut c_void,
) -> i32 {
    i32::from(JAVA_VM.load(Ordering::Acquire) != 0)
}

/// What one `prepare_worker` call reported, as a code the test can assert on.
///
/// The test cannot read a Rust enumeration, and a string would need the JNI
/// string interface for no gain here.
const PREPARED: i32 = 1;
const FAILED: i32 = 2;
const NOTHING: i32 = 3;

/// Converts one result into the code above.
fn code(setup: &WorkerSetup) -> i32 {
    match *setup {
        WorkerSetup::Prepared { .. } => PREPARED,
        WorkerSetup::Failed { .. } => FAILED,
        _ => NOTHING,
    }
}

/// Prepares a **new** thread, the way the worker does.
///
/// The call has to run on a thread that the virtual machine has never seen,
/// because the test thread already belongs to it and would prove nothing. The
/// worker is exactly such a thread: Fidelity creates it.
#[unsafe(no_mangle)]
pub extern "system" fn Java_fidelity_probe_Harness_prepareOnNewThread(
    _env: *mut c_void,
    _class: *mut c_void,
) -> i32 {
    let address = JAVA_VM.load(Ordering::Acquire);
    std::thread::spawn(move || {
        let environment = AndroidEnvironment::with_java_vm(address);
        code(&environment.prepare_worker())
    })
    .join()
    .unwrap_or(FAILED)
}

/// Reports whether the probe finds the virtual machine without the host.
///
/// It returns 1 when the probe found the same machine that the runtime handed
/// this library, 2 when it found a different one, and 0 when it found none.
/// The comparison is the point: a call that returned some other pointer would
/// attach the worker to the wrong machine.
#[unsafe(no_mangle)]
pub extern "system" fn Java_fidelity_probe_Harness_findsTheSameVirtualMachine(
    _env: *mut c_void,
    _class: *mut c_void,
) -> i32 {
    let from_host = JAVA_VM.load(Ordering::Acquire);
    match fidelity_probe_android::running_virtual_machine() {
        Some(found) if found == from_host => 1,
        Some(_) => 2,
        None => 0,
    }
}

/// Prepares a new thread with no host handle, so discovery is the only path.
#[unsafe(no_mangle)]
pub extern "system" fn Java_fidelity_probe_Harness_prepareByDiscoveryOnly(
    _env: *mut c_void,
    _class: *mut c_void,
) -> i32 {
    std::thread::spawn(|| code(&AndroidEnvironment::new().prepare_worker()))
        .join()
        .unwrap_or(FAILED)
}

/// The first four bytes of the signing-certificate digest that the probe reads.
///
/// The probe walks the archive that this process runs from. The test compares
/// this against the digest that `PackageManager` reports for the same package,
/// because the whole route exists to avoid that interface, and only an
/// agreement proves that avoiding it costs nothing.
///
/// It returns 0 when the probe found no certificate, which no installed
/// application should produce.
#[unsafe(no_mangle)]
pub extern "system" fn Java_fidelity_probe_Harness_signerPrefix(
    _env: *mut c_void,
    _class: *mut c_void,
) -> i32 {
    let Observation::Fact(identity) = AndroidEnvironment::new().code_identity() else {
        return 0;
    };
    let Some(signer) = identity.signer() else {
        return 0;
    };
    // The material is the digest as lowercase hexadecimal, because a build
    // states its identity in a string. Eight digits are the first four bytes.
    let Ok(text) = core::str::from_utf8(signer.material()) else {
        return 0;
    };
    let Some(prefix) = text.get(..8) else {
        return 0;
    };
    u32::from_str_radix(prefix, 16).map_or(0, |value| i32::from_ne_bytes(value.to_ne_bytes()))
}

/// The file name of this library, which the application loads by name.
///
/// The dispatch check below compares the answer of the probe against it.
const THIS_LIBRARY: &str = "/libfidelity_harness.so";

/// What the dispatch check reports about the image that the probe selected.
const THIS_ONE: i32 = 1;
const ANOTHER: i32 = 2;
const NONE: i32 = 0;

/// Whether the probe reads the dispatch table of the library of the host.
///
/// **This is the decisive test for dispatch on Android, and only an
/// application process can run it.** An application forks from zygote, so its
/// main image is `/system/bin/app_process64`. Every application on the device
/// shares that binary, and no call of the host reaches its table. The four
/// other platforms read the main image, and Android must read the library that
/// holds Fidelity instead. A shell binary cannot prove the difference, because
/// there the two are one image.
///
/// It returns 1 when the probe named this library, 2 when it named another
/// image, and 0 when the loader named none.
#[unsafe(no_mangle)]
pub extern "system" fn Java_fidelity_probe_Harness_dispatchImageIsThisLibrary(
    _env: *mut c_void,
    _class: *mut c_void,
) -> i32 {
    match fidelity_probe_android::dispatch_image_path() {
        Some(path) if path.ends_with(THIS_LIBRARY) => THIS_ONE,
        Some(_) => ANOTHER,
        None => NONE,
    }
}

/// How many dispatch targets the probe reports in this process.
///
/// The count states that the walk answered here, and not only in the shell
/// binary that the unit tests run. It returns 0 when the probe reports no
/// fact.
#[unsafe(no_mangle)]
pub extern "system" fn Java_fidelity_probe_Harness_dispatchTargetCount(
    _env: *mut c_void,
    _class: *mut c_void,
) -> i32 {
    let Observation::Fact(targets) = AndroidEnvironment::new().dispatch_targets() else {
        return 0;
    };
    i32::try_from(targets.targets().len()).unwrap_or(i32::MAX)
}

/// How long one measurement runs, and the smallest number of runs it takes.
///
/// The bound matches `crates/probe/measure.rs`. The run count does not, and
/// the statistic is the reason. That loop reports a mean, which every sample
/// improves. This loop reports the fastest call, which needs enough samples to
/// find a quiet one. Measured on 2026-08-20: at 10 runs one cycle reported
/// 12.2 ms, 12.6 ms, 20.0 ms, and 26.6 ms, and at 100 runs the same cycle on
/// the same machine reported 11.0 ms, 11.3 ms, and 11.3 ms. The 200 ms bound
/// alone gives a 10 ms cycle about 15 samples, and 15 samples rarely hold a
/// quiet one.
const BOUND: Duration = Duration::from_millis(200);
const RUNS: u32 = 100;

/// The fastest cost of one identity read in this process, in microseconds.
///
/// The `cost` example measures a shell binary, which maps no archive and
/// therefore stops early. Only an application process pays the whole route:
/// the command line, the mapping table, and the archive itself. That is the
/// cost a host carries on every worker cycle, and
/// `docs/plan/07-state-and-budgets.md` holds the recorded ceiling.
///
/// The read goes through `&dyn Environment`, because the engine holds
/// `Box<dyn Environment>` and because an indirect call is the only form the
/// optimizer cannot lift out of the loop.
#[unsafe(no_mangle)]
pub extern "system" fn Java_fidelity_probe_Harness_identityCostMicros(
    _env: *mut c_void,
    _class: *mut c_void,
) -> i32 {
    let probe = AndroidEnvironment::new();
    let environment: &dyn Environment = &probe;
    micros(|| {
        black_box(black_box(environment).code_identity());
    })
}

/// The fastest cost of one worker cycle in this process, in microseconds.
///
/// The cycle is every read that a detector makes, and the worker makes them
/// all on each pass. The identity read runs twice, because platform trust and
/// expected identity are two detectors and each one reads for itself.
///
/// The list below is `Detectors::scan_cheap`, in its order, and it must stay
/// that way. Until 2026-08-20 it held six of the eight, and it omitted
/// `system_build` and `machine_host`, so the ceiling gate covered neither and
/// the recorded cycle understated a real one. A review found that, and
/// `READS` in `Harness.kt` names the same eight.
#[unsafe(no_mangle)]
pub extern "system" fn Java_fidelity_probe_Harness_cycleCostMicros(
    _env: *mut c_void,
    _class: *mut c_void,
) -> i32 {
    let probe = AndroidEnvironment::new();
    let environment: &dyn Environment = &probe;
    // The value matches no archive. A comparison costs the same either way,
    // because the archive read in front of it is the whole cost.
    let expected =
        ExpectedIdentity::new().android(Choice::Value(CertificateSha256::from_bytes([0; 32])));
    micros(|| {
        let probe = black_box(environment);
        black_box(probe.code_identity());
        black_box(probe.identity_match(&expected));
        black_box(probe.tracer_state());
        black_box(probe.code_regions());
        black_box(probe.code_origin());
        black_box(probe.dispatch_targets());
        black_box(probe.system_build());
        black_box(probe.machine_host());
    })
}

/// What this call returns for an index that names no read.
const NO_SUCH_READ: i32 = -1;

/// The fastest cost of one read of the cycle, in microseconds, by index.
///
/// A cycle is one number, and one number names no cause. On 2026-08-20 this
/// call reported 26.6 ms against a recorded 2.4 ms, the ceiling row failed, and
/// nothing stated which read had moved. This call answers that, so the next
/// such move names itself. Every read turned out to be innocent, and
/// `tests/platform/README.md` holds what was not.
///
/// The index follows the order that
/// [`Java_fidelity_probe_Harness_cycleCostMicros`] reads in. An index outside
/// that range returns [`NO_SUCH_READ`], which the test separates from a cost.
#[unsafe(no_mangle)]
pub extern "system" fn Java_fidelity_probe_Harness_readCostMicros(
    _env: *mut c_void,
    _class: *mut c_void,
    which: i32,
) -> i32 {
    let probe = AndroidEnvironment::new();
    let environment: &dyn Environment = &probe;
    let expected =
        ExpectedIdentity::new().android(Choice::Value(CertificateSha256::from_bytes([0; 32])));
    match which {
        0 => micros(|| {
            black_box(black_box(environment).code_identity());
        }),
        1 => micros(|| {
            black_box(black_box(environment).identity_match(&expected));
        }),
        2 => micros(|| {
            black_box(black_box(environment).tracer_state());
        }),
        3 => micros(|| {
            black_box(black_box(environment).code_regions());
        }),
        4 => micros(|| {
            black_box(black_box(environment).code_origin());
        }),
        5 => micros(|| {
            black_box(black_box(environment).dispatch_targets());
        }),
        6 => micros(|| {
            black_box(black_box(environment).system_build());
        }),
        7 => micros(|| {
            black_box(black_box(environment).machine_host());
        }),
        _ => NO_SUCH_READ,
    }
}

/// The literal that the guarded constant below carries.
///
/// The instrumented test holds the same text, and it compares the four bytes
/// that [`Java_fidelity_probe_Harness_guardedPrefix`] returns.
const GUARDED_LITERAL: &str = "api.example.com";

/// What the guarded read reports when `start()` itself failed.
const NO_START: i32 = 0;

/// The first four bytes of one guarded constant, as this process reads it.
///
/// This is the repackage control for `guarded!()`, and only an application
/// process can run it. The build binds to the signing certificate of the
/// archive, so an archive that another key signed derives another key and
/// every guarded constant decrypts to something else. No error reports that,
/// which is the whole point of the design, so the test compares values.
///
/// It returns 0 when `start()` failed, which is a different outcome from a
/// wrong value and the test separates the two.
#[unsafe(no_mangle)]
pub extern "system" fn Java_fidelity_probe_Harness_guardedPrefix(
    _env: *mut c_void,
    _class: *mut c_void,
) -> i32 {
    let Ok(handle) = fidelity::new().start() else {
        return NO_START;
    };
    let value = fidelity::guarded!(&handle, "api.example.com");
    match value.as_bytes() {
        [a, b, c, d, ..] => i32::from_be_bytes([*a, *b, *c, *d]),
        _ => NO_START,
    }
}

/// The first four bytes of the literal that the guarded constant carries.
///
/// The test compares this against the value above. A test that held the
/// expected number would stop being a comparison of two independent things.
#[unsafe(no_mangle)]
pub extern "system" fn Java_fidelity_probe_Harness_guardedLiteralPrefix(
    _env: *mut c_void,
    _class: *mut c_void,
) -> i32 {
    match GUARDED_LITERAL.as_bytes() {
        [a, b, c, d, ..] => i32::from_be_bytes([*a, *b, *c, *d]),
        _ => NO_START,
    }
}

/// Runs one measurement and reports the fastest call, in microseconds.
///
/// The `cost` examples report a mean, and this reports a minimum, because the
/// two run in different processes. An example owns its process. This harness
/// shares one process with every other instrumented test, and one of them
/// starts a Fidelity runtime whose worker then scans for the rest of the run.
/// A mean would measure that worker as well, and it would move with the order
/// that JUnit picks. The fastest call measures the work itself, so the ceiling
/// holds whatever else runs.
fn micros(mut call: impl FnMut()) -> i32 {
    let start = Instant::now();
    let mut runs = 0_u32;
    let mut best = Duration::MAX;
    while runs < RUNS || start.elapsed() < BOUND {
        let one = Instant::now();
        call();
        best = best.min(one.elapsed());
        runs = runs.saturating_add(1);
    }
    i32::try_from(best.as_micros()).unwrap_or(i32::MAX)
}
