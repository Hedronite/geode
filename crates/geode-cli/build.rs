//! Build-time guard for the test-only `test-trusted-root` feature.
//!
//! `src/cmd/run.rs` refuses the feature when debug assertions are off. A
//! custom profile can turn debug assertions on with optimizations still
//! enabled, so this script also refuses the feature at any `opt-level`
//! other than 0. Test and dev builds use opt-level 0 and are unaffected.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_TEST_TRUSTED_ROOT");
    let feature = std::env::var_os("CARGO_FEATURE_TEST_TRUSTED_ROOT").is_some();
    let opt = std::env::var("OPT_LEVEL").unwrap_or_default();
    if let Some(why) = refusal(feature, &opt) {
        panic!("{why}");
    }
}

/// Why this build must not enable `test-trusted-root`, if it must not.
///
/// Debug assertions are not checked here: older Cargo does not tell build
/// scripts about them, and `src/cmd/run.rs` already refuses that case.
fn refusal(feature: bool, opt_level: &str) -> Option<String> {
    if !feature {
        return None;
    }
    if opt_level != "0" {
        return Some(format!(
            "feature `test-trusted-root` is test-only; refusing an optimized build (opt-level {opt_level})"
        ));
    }
    None
}
