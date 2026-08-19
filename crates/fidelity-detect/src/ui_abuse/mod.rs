//! Detectors for the `UiAbuse` category.
//!
//! The category asks one question: does another application read or drive this
//! application's user interface? An attacker who draws over a window collects
//! what a person meant for the host, and an attacker who records the screen
//! reads it.
//!
//! This category takes its input from the host, and every other category reads
//! the operating system. A measurement decided that, and
//! [detectors and platforms](../../../../docs/plan/04-detectors-and-platforms.md)
//! holds it: no interface states that another application draws above this
//! one, and the flag that does states it on a touch that a `View` receives. A
//! library holds no `View`, so the host reads it and reports it.
//!
//! The [plan](../../../../docs/plan/04-detectors-and-platforms.md) excludes one
//! mechanism here. The presence of an accessibility service is not decisive
//! evidence, because assistive technology is a legitimate and protected use. A
//! clean Android emulator already holds 17 packages that ask to draw over
//! other applications, which is the same reason in another form.

mod host_report;

pub use host_report::HOST_REPORT;

pub use host_report::host_report;
