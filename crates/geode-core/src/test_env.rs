//! Process-wide env lock for unit tests.
//!
//! `HOME`, `XDG_CONFIG_HOME`, and `GEODE_KEY_FILE` are process globals.
//! Tests that read or write them take [`EnvGuard`] so they cannot interleave,
//! and the guard puts the previous values back on drop, including after a panic.
//!
//! A panic while the guard is held poisons [`ENV_LOCK`]. `lock` recovers the
//! guard so later tests still run; the env is restored before the poison
//! is observed.

use std::ffi::{OsStr, OsString};
use std::sync::{Mutex, MutexGuard};

/// Serializes tests that touch [`VARS`].
pub(crate) static ENV_LOCK: Mutex<()> = Mutex::new(());

const VARS: [&str; 3] = ["HOME", "XDG_CONFIG_HOME", "GEODE_KEY_FILE"];

/// Holds [`ENV_LOCK`] and restores the key-path env vars on drop.
#[must_use = "dropping the guard releases the env lock"]
#[derive(Debug)]
pub(crate) struct EnvGuard {
    lock: MutexGuard<'static, ()>,
    saved: [Option<OsString>; 3],
}

impl EnvGuard {
    /// Lock the process env and snapshot the key-path variables.
    pub(crate) fn lock() -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let saved = VARS.map(std::env::var_os);
        Self { lock, saved }
    }

    /// Set `HOME`, `XDG_CONFIG_HOME`, or `GEODE_KEY_FILE`.
    ///
    /// Other names panic: the guard would not restore them.
    pub(crate) fn set(&self, key: &str, val: impl AsRef<OsStr>) {
        self.covered(key);
        std::env::set_var(key, val);
    }

    /// Remove `HOME`, `XDG_CONFIG_HOME`, or `GEODE_KEY_FILE`.
    ///
    /// Other names panic: the guard would not restore them.
    pub(crate) fn remove(&self, key: &str) {
        self.covered(key);
        std::env::remove_var(key);
    }

    fn covered(&self, key: &str) {
        let _held = &self.lock;
        assert!(
            VARS.contains(&key),
            "EnvGuard only covers HOME, XDG_CONFIG_HOME, and GEODE_KEY_FILE, not {key}"
        );
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, prev) in VARS.iter().zip(self.saved.iter()) {
            match prev {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::EnvGuard;

    #[test]
    fn restores_home_on_drop() {
        let before = std::env::var_os("HOME");
        {
            let env = EnvGuard::lock();
            env.set("HOME", "/tmp/geode-env-lock-sentinel");
            assert_eq!(
                std::env::var_os("HOME").as_deref(),
                Some(std::ffi::OsStr::new("/tmp/geode-env-lock-sentinel"))
            );
        }
        assert_eq!(std::env::var_os("HOME"), before);
    }

    #[test]
    fn restores_xdg_after_panic() {
        let before = std::env::var_os("XDG_CONFIG_HOME");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let env = EnvGuard::lock();
            env.set("XDG_CONFIG_HOME", "/tmp/geode-env-lock-xdg");
            panic!("unwind while the env guard is held");
        }));
        assert!(result.is_err());
        assert_eq!(std::env::var_os("XDG_CONFIG_HOME"), before);
    }
}
