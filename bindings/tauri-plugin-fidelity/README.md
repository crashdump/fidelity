# Tauri plugin for Fidelity

This crate starts Fidelity during the Tauri setup phase. It stores the runtime handle in Tauri
state for Rust code.

The plugin exposes no WebView interface. JavaScript cannot read a report or change a policy.

```rust,no_run
use tauri_plugin_fidelity::FidelityExt;

let builder = tauri::Builder::default().plugin(tauri_plugin_fidelity::init(fidelity::new()));

// A Rust handler can use `app.ensure_fidelity_allowed()` before protected work.
# let _ = builder;
```
