//! A Rust-only Tauri 2 lifecycle adapter for Fidelity.
//!
//! [`init`] starts Fidelity during the Tauri setup phase. The plugin stores
//! the [`fidelity::Handle`] in Tauri state. [`FidelityExt`] gives Rust code a
//! short path to the handle and the denial check.
//!
//! The plugin exposes no `WebView` interface. A frontend cannot read a report,
//! change a policy, or report a host observation through this crate.

#![forbid(unsafe_code)]

use core::fmt;

use tauri::{Manager, Runtime, plugin::TauriPlugin};

/// Creates the Tauri plugin with one Fidelity builder.
///
/// The setup hook starts Fidelity and stores its handle in Tauri state.
///
/// A failed Fidelity start fails the Tauri setup phase.
#[must_use]
pub fn init<R: Runtime>(builder: fidelity::Builder) -> TauriPlugin<R> {
    tauri::plugin::Builder::new("fidelity")
        .setup(move |app, _api| {
            let handle = builder.start()?;
            if !app.manage(handle) {
                return Err(SetupError.into());
            }
            Ok(())
        })
        .build()
}

/// Rust access to the Fidelity state that [`init`] stores.
pub trait FidelityExt<R: Runtime>: Manager<R> {
    /// Returns a clone of the process-wide Fidelity handle.
    ///
    /// # Panics
    ///
    /// Panics when the application did not install [`init`].
    fn fidelity_handle(&self) -> fidelity::Handle {
        self.state::<fidelity::Handle>().inner().clone()
    }

    /// Reports whether a protected operation may run.
    ///
    /// # Errors
    ///
    /// Returns [`fidelity::Denied`] when the runtime denies the operation.
    fn ensure_fidelity_allowed(&self) -> Result<(), fidelity::Denied> {
        self.fidelity_handle().ensure_allowed()
    }
}

impl<R: Runtime, T: Manager<R>> FidelityExt<R> for T {}

#[derive(Debug)]
struct SetupError;

impl fmt::Display for SetupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Tauri state already holds a Fidelity handle")
    }
}

impl std::error::Error for SetupError {}

#[cfg(test)]
mod tests {
    use super::{FidelityExt, init};

    fn the_extension_surface_compiles<R, T>(manager: &T)
    where
        R: tauri::Runtime,
        T: FidelityExt<R>,
    {
        let _: fidelity::Handle = manager.fidelity_handle();
        let _: Result<(), fidelity::Denied> = manager.ensure_fidelity_allowed();
    }

    #[test]
    fn the_extension_surface_has_the_locked_types() {
        let _ = the_extension_surface_compiles::<
            tauri::test::MockRuntime,
            tauri::AppHandle<tauri::test::MockRuntime>,
        >;
    }

    #[test]
    fn setup_stores_the_runtime_handle_in_tauri_state() {
        let built = tauri::test::mock_builder()
            .plugin(init(fidelity::new()))
            .build(tauri::test::mock_context(tauri::test::noop_assets()));
        let Ok(app) = built else {
            panic!("the Tauri setup must start Fidelity")
        };

        assert!(!app.fidelity_handle().snapshot().detectors().is_empty());
    }
}
