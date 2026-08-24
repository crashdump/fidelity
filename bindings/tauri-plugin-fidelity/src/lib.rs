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
    /// Returns the process-wide Fidelity handle when the plugin installed it.
    ///
    /// # Errors
    ///
    /// Returns [`FidelityStateError`] when the application did not install
    /// [`init`].
    fn try_fidelity_handle(&self) -> Result<fidelity::Handle, FidelityStateError> {
        self.try_state::<fidelity::Handle>()
            .map(|state| state.inner().clone())
            .ok_or(FidelityStateError)
    }

    /// Returns a clone of the process-wide Fidelity handle.
    ///
    /// # Panics
    ///
    /// Panics when the application did not install [`init`].
    fn fidelity_handle(&self) -> fidelity::Handle {
        match self.try_fidelity_handle() {
            Ok(handle) => handle,
            Err(error) => panic!("{error}"),
        }
    }

    /// Reports whether a protected operation may run.
    ///
    /// # Errors
    ///
    /// Returns [`fidelity::Denied`] when the runtime denies the operation.
    fn ensure_fidelity_allowed(&self) -> Result<(), fidelity::Denied> {
        self.fidelity_handle().ensure_allowed()
    }

    /// Reports whether a protected operation may run without a panic path.
    ///
    /// # Errors
    ///
    /// Returns [`FidelityCheckError`] when state is absent or Fidelity denies.
    fn try_ensure_fidelity_allowed(&self) -> Result<(), FidelityCheckError> {
        self.try_fidelity_handle()
            .map_err(FidelityCheckError::State)?
            .ensure_allowed()
            .map_err(FidelityCheckError::Denied)
    }

    /// Reports one user-interface observation to Fidelity.
    ///
    /// # Errors
    ///
    /// Returns [`FidelityStateError`] when the application did not install
    /// [`init`].
    fn report_fidelity_ui_abuse(
        &self,
        observation: fidelity::UiObservation,
    ) -> Result<(), FidelityStateError> {
        self.try_fidelity_handle()?.report_ui_abuse(observation);
        Ok(())
    }
}

impl<R: Runtime, T: Manager<R>> FidelityExt<R> for T {}

/// The application did not install the Fidelity plugin state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FidelityStateError;

impl fmt::Display for FidelityStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the Tauri application did not install the Fidelity plugin")
    }
}

impl std::error::Error for FidelityStateError {}

/// A fallible protected-operation check did not permit the operation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FidelityCheckError {
    /// The application did not install the Fidelity plugin state.
    State(FidelityStateError),

    /// Fidelity denied the protected operation.
    Denied(fidelity::Denied),
}

impl fmt::Display for FidelityCheckError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => error.fmt(formatter),
            Self::Denied(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for FidelityCheckError {}

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
    use std::time::Duration;

    use super::{FidelityCheckError, FidelityExt, init};

    fn the_extension_surface_compiles<R, T>(manager: &T)
    where
        R: tauri::Runtime,
        T: FidelityExt<R>,
    {
        let _: fidelity::Handle = manager.fidelity_handle();
        let _: Result<fidelity::Handle, super::FidelityStateError> = manager.try_fidelity_handle();
        let _: Result<(), fidelity::Denied> = manager.ensure_fidelity_allowed();
        let _: Result<(), FidelityCheckError> = manager.try_ensure_fidelity_allowed();
        let _: Result<(), super::FidelityStateError> =
            manager.report_fidelity_ui_abuse(fidelity::UiObservation::Overlay);
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
            .plugin(init(fidelity::new().ui_abuse(
                fidelity::Action::Deny,
                fidelity::SignalStrength::Medium,
            )))
            .build(tauri::test::mock_context(tauri::test::noop_assets()));
        let Ok(app) = built else {
            panic!("the Tauri setup must start Fidelity")
        };

        let handle = app.fidelity_handle();
        assert!(!handle.snapshot().detectors().is_empty());
        assert!(handle.wait_for_first_full_scan(Duration::from_secs(2)));
        assert!(
            app.report_fidelity_ui_abuse(fidelity::UiObservation::Overlay)
                .is_ok()
        );
        assert!(matches!(
            app.try_ensure_fidelity_allowed(),
            Err(FidelityCheckError::Denied(_))
        ));
    }

    #[test]
    fn fallible_access_reports_an_absent_plugin() {
        let built = tauri::test::mock_builder()
            .build(tauri::test::mock_context(tauri::test::noop_assets()));
        let Ok(app) = built else {
            panic!("the Tauri test application must build")
        };

        assert!(app.try_fidelity_handle().is_err());
        assert!(matches!(
            app.try_ensure_fidelity_allowed(),
            Err(FidelityCheckError::State(_))
        ));
    }
}
