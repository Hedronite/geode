//! Build-time guard for the test-only `test-trusted-root` feature.
//!
//! `src/inject.rs` refuses the feature when debug assertions are off. A
//! custom profile can turn debug assertions on with optimizations still
//! enabled, so this script also refuses the feature at any `opt-level`
//! other than 0. Debug assertions are not checked here: older Cargo does
//! not pass that cfg to build scripts. Test and dev builds use opt-level 0
//! and are unaffected.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_TEST_TRUSTED_ROOT");
    let feature = std::env::var_os("CARGO_FEATURE_TEST_TRUSTED_ROOT").is_some();
    let opt = std::env::var("OPT_LEVEL").unwrap_or_default();
    if feature && opt != "0" {
        panic!(
            "feature `test-trusted-root` is test-only; refusing an optimized build (opt-level {opt})"
        );
    }
}
