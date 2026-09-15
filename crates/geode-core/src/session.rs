//! Unlock session — hold EK, zeroize ISK (06-agent-plane §2; 14-tui §3).
//!
//! G4 (v0.2.0): the session types the TUI and `geode unlock` will drive,
//! kept TUI-free so it is testable headless. [`Session::unlock`] loads ISK,
//! derives EK, and **zeroizes ISK** before returning; the session holds
//! only EK plus public ids. [`Session::lock`] drops EK (zeroized on drop
//! via `EpochKey`'s `Secret32`). An idle timeout (default 15 min, `0` =
//! never) is enforced by [`Session::lock_if_idle`], polled by the host
//! (TUI tick / CLI loop).
//!
//! No session file is written by this module: the in-process session is
//! the source of truth. The CLI's `$XDG_RUNTIME_DIR/geode/<vault_id>.session`
//! sealing is a CLI concern (06 §2), not core. This module depends on no
//! TUI crate (`ratatui` / `crossterm` stay out of `geode-grotto`).

use crate::kdf::{
    derive_epoch_key, derive_key_id, Epoch, EpochKey, IdentitySecret, KeyId, VaultId,
};
use crate::wrap::{unwrap_identity_passphrase, WrappedKey};
use crate::{Error, Result};
use std::time::{Duration, Instant};

/// Default idle lock: 15 minutes (14-tui §3.3).
pub const DEFAULT_IDLE_LOCK: Duration = Duration::from_secs(15 * 60);

/// A live unlock session (06 §2; 14-tui §3).
///
/// Holds EK and public ids only — **never ISK**. [`Session::unlock`]
/// zeroizes ISK before constructing this. [`Session::lock`] drops EK
/// (zeroized on drop). After `lock` the session is inert: [`Session::ek`]
/// returns `Err(Error::Locked)`.
#[derive(Debug)]
pub struct Session {
    /// Live epoch key. `None` once locked (zeroized on drop).
    ek: Option<EpochKey>,
    vault_id: VaultId,
    epoch: Epoch,
    key_id: KeyId,
    context_label: String,
    idle_timeout: Duration,
    last_activity: Instant,
}

impl Session {
    /// Unlock: derive EK from ISK + vault + epoch + context, then zeroize ISK.
    ///
    /// The caller passes the ISK by value; this function derives EK and
    /// drops ISK (zeroized via `IdentitySecret`'s `Secret32` on drop) before
    /// returning the session. The session never retains ISK. `idle_timeout`
    /// of `Duration::ZERO` means "never idle-lock".
    pub fn unlock(
        isk: IdentitySecret,
        vault_id: VaultId,
        epoch: Epoch,
        context_label: &str,
        idle_timeout: Duration,
    ) -> Result<Self> {
        Self::unlock_at(
            isk,
            vault_id,
            epoch,
            context_label,
            idle_timeout,
            Instant::now(),
        )
    }

    /// Unlock with an explicit "now" for the idle-timer origin.
    ///
    /// Same as [`Session::unlock`] but the caller supplies the instant used
    /// as the last-activity baseline, so idle-lock tests can drive time
    /// deterministically via [`Session::lock_if_idle`].
    pub fn unlock_at(
        isk: IdentitySecret,
        vault_id: VaultId,
        epoch: Epoch,
        context_label: &str,
        idle_timeout: Duration,
        now: Instant,
    ) -> Result<Self> {
        let key_id = derive_key_id(&isk)?;
        let ek = derive_epoch_key(&isk, vault_id, epoch, context_label)?;
        // ISK drops here: zeroized by Secret32::Drop. We do not hold it.
        drop(isk);
        Ok(Self {
            ek: Some(ek),
            vault_id,
            epoch,
            key_id,
            context_label: context_label.to_string(),
            idle_timeout,
            last_activity: now,
        })
    }

    /// Convenience: unwrap a passphrase-wrapped `GKEY` then unlock.
    ///
    /// Loads ISK by unwrapping `wrapped` with `passphrase` (Argon2id +
    /// AEGIS-256-X2), derives EK, and zeroizes ISK — all in one call. Wrong
    /// passphrase or tampered wrap surfaces `Error::AuthFail`.
    pub fn unlock_wrapped(
        wrapped: &WrappedKey,
        passphrase: &[u8],
        vault_id: VaultId,
        epoch: Epoch,
        context_label: &str,
        idle_timeout: Duration,
    ) -> Result<Self> {
        let isk = unwrap_identity_passphrase(wrapped, passphrase)?;
        Self::unlock(isk, vault_id, epoch, context_label, idle_timeout)
    }

    /// Borrow the live EK, or `Err(Error::Locked)` if the session is locked.
    pub fn ek(&self) -> Result<&EpochKey> {
        self.ek.as_ref().ok_or(Error::Locked)
    }

    /// Public `vault_id` (safe for chrome / logs).
    #[must_use]
    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// Public `epoch` (safe for chrome).
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Public `key_id` (safe for chrome / logs).
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// Context label bound into EK derivation.
    #[must_use]
    pub fn context_label(&self) -> &str {
        &self.context_label
    }

    /// Configured idle timeout (`Duration::ZERO` = never).
    #[must_use]
    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// `true` while EK is live.
    #[must_use]
    pub fn is_unlocked(&self) -> bool {
        self.ek.is_some()
    }

    /// `true` after `lock` or idle-lock.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.ek.is_none()
    }

    /// Mark activity now (resets the idle timer). No-op when locked.
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Lock now: drop and zeroize EK. Idempotent.
    pub fn lock(&mut self) {
        self.ek = None; // EpochKey -> Secret32 zeroizes on drop
    }

    /// Lock if the idle timeout has elapsed since last activity. Returns
    /// `true` if this call locked the session. `idle_timeout == ZERO` never
    /// locks. No-op when already locked. `now` is taken explicitly so tests
    /// and hosts with synthetic clocks can drive the timer deterministically.
    pub fn lock_if_idle(&mut self, now: Instant) -> bool {
        if self.ek.is_none() || self.idle_timeout == Duration::ZERO {
            return false;
        }
        let elapsed = now.checked_duration_since(self.last_activity);
        match elapsed {
            Some(d) if d >= self.idle_timeout => {
                self.lock();
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wrap::{wrap_identity_passphrase, Argon2Params};

    fn isk() -> IdentitySecret {
        IdentitySecret::from_bytes([0x42; 32])
    }
    fn vault() -> VaultId {
        VaultId([0x11; 16])
    }

    #[test]
    fn unlock_holds_correct_ek_and_drops_isk() {
        // Re-derive EK independently from the same ISK bytes and compare.
        let v = vault();
        let e = Epoch(1);
        let ctx = "tui";
        let expected = derive_epoch_key(&isk(), v, e, ctx).unwrap();

        let s = Session::unlock(isk(), v, e, ctx, DEFAULT_IDLE_LOCK).unwrap();
        assert!(s.is_unlocked());
        assert!(!s.is_locked());
        assert_eq!(s.ek().unwrap().as_bytes(), expected.as_bytes());
    }

    #[test]
    fn unlock_zeroizes_isk_by_consuming_it() {
        // ISK is moved into unlock; the session exposes no ISK accessor.
        let v = vault();
        let s = Session::unlock(isk(), v, Epoch(1), "", Duration::ZERO).unwrap();
        // Only public ids + EK are reachable. key_id matches the ISK.
        let expected_id = derive_key_id(&IdentitySecret::from_bytes([0x42; 32])).unwrap();
        assert_eq!(s.key_id().0, expected_id.0);
        assert_eq!(s.vault_id(), v);
    }

    #[test]
    fn different_contexts_yield_different_ek() {
        let v = vault();
        let a = Session::unlock(isk(), v, Epoch(1), "alpha", Duration::ZERO).unwrap();
        let b = Session::unlock(isk(), v, Epoch(1), "beta", Duration::ZERO).unwrap();
        assert_ne!(a.ek().unwrap().as_bytes(), b.ek().unwrap().as_bytes());
    }

    #[test]
    fn lock_drops_ek_and_is_idempotent() {
        let mut s = Session::unlock(isk(), vault(), Epoch(1), "", DEFAULT_IDLE_LOCK).unwrap();
        assert!(s.is_unlocked());
        s.lock();
        assert!(s.is_locked());
        assert!(matches!(s.ek(), Err(Error::Locked)));
        // Idempotent: locking again is fine.
        s.lock();
        assert!(s.is_locked());
    }

    #[test]
    fn unlock_wrapped_roundtrip() {
        let isk = isk();
        let passphrase = b"correct horse battery staple";
        let wrapped =
            wrap_identity_passphrase(&isk, passphrase, Argon2Params::DEFAULT_CHEAP).expect("wrap");
        let s = Session::unlock_wrapped(
            &wrapped,
            passphrase,
            vault(),
            Epoch(1),
            "tui",
            DEFAULT_IDLE_LOCK,
        )
        .expect("unlock wrapped");
        let expected = derive_epoch_key(&isk, vault(), Epoch(1), "tui").unwrap();
        assert_eq!(s.ek().unwrap().as_bytes(), expected.as_bytes());
    }

    #[test]
    fn unlock_wrapped_wrong_passphrase_is_auth_fail() {
        let wrapped =
            wrap_identity_passphrase(&isk(), b"right", Argon2Params::DEFAULT_CHEAP).expect("wrap");
        let r =
            Session::unlock_wrapped(&wrapped, b"wrong", vault(), Epoch(1), "", DEFAULT_IDLE_LOCK);
        assert!(matches!(r, Err(Error::AuthFail)), "got {r:?}");
    }

    #[test]
    fn idle_lock_fires_after_timeout() {
        let t0 = Instant::now();
        let mut s =
            Session::unlock_at(isk(), vault(), Epoch(1), "", Duration::from_millis(1), t0).unwrap();
        // Just before timeout: not locked.
        let t1 = t0 + Duration::from_micros(500);
        assert!(!s.lock_if_idle(t1));
        assert!(s.is_unlocked());
        // At/after timeout: locked.
        let t2 = t0 + Duration::from_millis(2);
        assert!(s.lock_if_idle(t2));
        assert!(s.is_locked());
    }

    #[test]
    fn idle_timeout_zero_never_locks() {
        let t0 = Instant::now();
        let mut s = Session::unlock_at(isk(), vault(), Epoch(1), "", Duration::ZERO, t0).unwrap();
        let far = t0 + Duration::from_secs(86_400);
        assert!(!s.lock_if_idle(far));
        assert!(s.is_unlocked());
    }

    #[test]
    fn touch_resets_idle_timer() {
        let t0 = Instant::now();
        let mut s = Session::unlock_at(isk(), vault(), Epoch(1), "", Duration::from_millis(10), t0)
            .unwrap();
        // Advance near timeout, then simulate a fresh activity at t1.
        let t1 = t0 + Duration::from_millis(8);
        assert!(!s.lock_if_idle(t1));
        s.last_activity = t1;
        let t2 = t1 + Duration::from_millis(8);
        assert!(!s.lock_if_idle(t2), "touched, should not be idle yet");
        let t3 = t1 + Duration::from_millis(11);
        assert!(s.lock_if_idle(t3), "past the new timeout, should lock");
    }

    #[test]
    fn lock_if_idle_noop_when_already_locked() {
        let t0 = Instant::now();
        let mut s =
            Session::unlock_at(isk(), vault(), Epoch(1), "", Duration::from_millis(1), t0).unwrap();
        s.lock();
        let far = t0 + Duration::from_secs(60);
        assert!(!s.lock_if_idle(far));
        assert!(s.is_locked());
    }

    #[test]
    fn public_ids_match_independent_derivation() {
        let v = vault();
        let e = Epoch(7);
        let s = Session::unlock(isk(), v, e, "ctx", Duration::ZERO).unwrap();
        assert_eq!(s.vault_id(), v);
        assert_eq!(s.epoch(), e);
        assert_eq!(s.context_label(), "ctx");
        let expected_id = derive_key_id(&isk()).unwrap();
        assert_eq!(s.key_id().0, expected_id.0);
    }
}
