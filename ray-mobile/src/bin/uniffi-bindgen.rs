//! Standalone bindgen CLI so `uniffi-bindgen generate --library <cdylib>` runs
//! against this crate's own UniFFI version, with no separately installed tool.
fn main() {
    uniffi::uniffi_bindgen_main()
}
