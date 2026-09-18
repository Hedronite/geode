//! G1 (v0.2.3) — policy CLI fixtures against the shipped `geode` binary
//! (10-policy).
//!
//! Drives `target/debug/geode` (via `CARGO_BIN_EXE_geode`):
//!
//! 1. `policy_show_set_check` — `policy show` on a policy-less vault
//!    prints the default (`human:local` admin on `""`); `policy set`
//!    seals a policy (no flags on the first seal); `show` then reports
//!    source `sealed`; `policy check` allow exits 0, deny exits 3 with
//!    JSON code `policy_deny`.
//! 2. `policy_set_break_glass` — rewriting an existing sealed policy
//!    without `--yes --break-glass` exits 1; with both flags it seals and
//!    prints the loud break-glass line on stderr (10-policy 4).
//! 3. `policy_fail_closed` — a tampered `policy.json.sealed` exits 2 on
//!    `show`; a policy whose `vault_id` does not match exits 1 on `set`;
//!    a token issue that would widen the sealed policy exits 3
//!    (10-policy 2.5, `token::issue_narrow`).
//!
//! No passphrases, no key bytes, no ISK in any captured output.

use std::path::Path;
use std::process::{Command, Output};

fn geode(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_geode"))
        .args(args)
        .current_dir(dir)
        .env_remove("GEODE_TOKEN")
        .output()
        .expect("spawn geode")
}

fn assert_ok(out: &Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn setup_vault(dir: &Path) {
    assert_ok(&geode(dir, &["keygen", "k.gkey"]), "keygen");
    assert_ok(
        &geode(dir, &["--key", "k.gkey", "vault", "init", "v.geode"]),
        "vault init",
    );
}

/// The vault's public id, via `policy show --output json` (default policy
/// carries it).
fn vault_id(dir: &Path) -> String {
    let show = geode(
        dir,
        &[
            "--key", "k.gkey", "--output", "json", "policy", "show", "v.geode",
        ],
    );
    assert_ok(&show, "policy show (id)");
    let doc: serde_json::Value = serde_json::from_slice(&show.stdout).expect("show json");
    doc["policy"]["vault_id"]
        .as_str()
        .expect("vault_id field")
        .to_owned()
}

/// A two-grant policy: `human:local` admin on `""`, `agent:oma`
/// list/read on `scratch/` capped at 64 KiB.
fn policy_json(vault_id: &str) -> String {
    format!(
        r#"{{
  "version": 1,
  "vault_id": "{vault_id}",
  "default": "deny",
  "principals": [
    {{"id": "human:local", "ops": ["list", "read", "write", "mount", "verify", "admin"], "prefixes": [""]}},
    {{"id": "agent:oma", "ops": ["list", "read"], "prefixes": ["scratch/"], "max_bytes": 65536}}
  ]
}}"#
    )
}

fn set_policy(dir: &Path, body: &str, extra: &[&str]) -> Output {
    std::fs::write(dir.join("policy.json"), body).expect("write policy.json");
    let mut args: Vec<&str> = vec![
        "--key",
        "k.gkey",
        "policy",
        "set",
        "v.geode",
        "--file",
        "policy.json",
    ];
    args.extend_from_slice(extra);
    geode(dir, &args)
}

#[test]
fn policy_show_set_check() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup_vault(dir);

    // No policy file: show prints the default policy (10-policy 3).
    let show = geode(dir, &["--key", "k.gkey", "policy", "show", "v.geode"]);
    assert_ok(&show, "policy show (default)");
    let text = String::from_utf8_lossy(&show.stdout);
    assert!(text.contains("human:local"), "default policy: {text}");
    assert!(
        String::from_utf8_lossy(&show.stderr).contains("default"),
        "source note on stderr"
    );

    // First seal needs no flags.
    let vid = vault_id(dir);
    let set = set_policy(dir, &policy_json(&vid), &[]);
    assert_ok(&set, "policy set (initial)");
    assert!(dir.join("v.geode/policy.json.sealed").is_file());

    // Show now reports the sealed source and both principals.
    let show2 = geode(
        dir,
        &[
            "--key", "k.gkey", "--output", "json", "policy", "show", "v.geode",
        ],
    );
    assert_ok(&show2, "policy show (sealed)");
    let doc: serde_json::Value = serde_json::from_slice(&show2.stdout).expect("show json");
    assert_eq!(doc["source"], "sealed");
    assert_eq!(
        doc["policy"]["principals"]
            .as_array()
            .expect("principals")
            .len(),
        2
    );
}

#[test]
fn policy_check_verdicts() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup_vault(dir);
    let vid = vault_id(dir);
    assert_ok(&set_policy(dir, &policy_json(&vid), &[]), "initial set");

    // check: allow exits 0.
    let allow = geode(
        dir,
        &[
            "--key",
            "k.gkey",
            "policy",
            "check",
            "v.geode",
            "--principal",
            "agent:oma",
            "--op",
            "read",
            "--path",
            "scratch/plan.md",
        ],
    );
    assert_ok(&allow, "policy check allow");
    assert!(String::from_utf8_lossy(&allow.stdout).contains("allow agent:oma read"));

    // check: deny exits 3; JSON mode carries code policy_deny.
    let deny = geode(
        dir,
        &[
            "--key",
            "k.gkey",
            "policy",
            "check",
            "v.geode",
            "--principal",
            "agent:oma",
            "--op",
            "write",
            "--path",
            "scratch/plan.md",
        ],
    );
    assert_eq!(
        deny.status.code(),
        Some(3),
        "deny exit: {}",
        String::from_utf8_lossy(&deny.stderr)
    );
    let deny_json = geode(
        dir,
        &[
            "--key",
            "k.gkey",
            "--output",
            "json",
            "policy",
            "check",
            "v.geode",
            "--principal",
            "agent:oma",
            "--op",
            "read",
            "--path",
            "keys/prod.pem",
        ],
    );
    assert_eq!(deny_json.status.code(), Some(3));
    let doc: serde_json::Value = serde_json::from_slice(&deny_json.stdout).expect("deny json");
    assert_eq!(doc["ok"], false);
    assert_eq!(doc["error"]["code"], "policy_deny");

    // Unknown op is a usage error (exit 1), never a silent deny.
    let bad_op = geode(
        dir,
        &[
            "--key",
            "k.gkey",
            "policy",
            "check",
            "v.geode",
            "--principal",
            "agent:oma",
            "--op",
            "explode",
            "--path",
            "scratch/x",
        ],
    );
    assert_eq!(bad_op.status.code(), Some(1));
}

#[test]
fn policy_set_break_glass() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup_vault(dir);
    let vid = vault_id(dir);
    assert_ok(&set_policy(dir, &policy_json(&vid), &[]), "initial set");

    // Rewrite without the flags: usage error, exit 1, file unchanged.
    let before = std::fs::read(dir.join("v.geode/policy.json.sealed")).expect("sealed bytes");
    let no_flags = set_policy(dir, &policy_json(&vid), &[]);
    assert_eq!(
        no_flags.status.code(),
        Some(1),
        "rewrite without flags: {}",
        String::from_utf8_lossy(&no_flags.stderr)
    );
    let after = std::fs::read(dir.join("v.geode/policy.json.sealed")).expect("sealed bytes");
    assert_eq!(before, after, "refused rewrite must not touch the file");

    // --yes alone is not enough; --break-glass alone is not enough.
    let yes_only = set_policy(dir, &policy_json(&vid), &["--yes"]);
    assert_eq!(yes_only.status.code(), Some(1));
    let bg_only = set_policy(dir, &policy_json(&vid), &["--break-glass"]);
    assert_eq!(bg_only.status.code(), Some(1));

    // Both flags: seals, and the override is printed loudly on stderr.
    let both = set_policy(dir, &policy_json(&vid), &["--yes", "--break-glass"]);
    assert_ok(&both, "break-glass rewrite");
    assert!(
        String::from_utf8_lossy(&both.stderr).contains("BREAK-GLASS"),
        "loud override line: {}",
        String::from_utf8_lossy(&both.stderr)
    );
}

#[test]
fn policy_fail_closed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup_vault(dir);
    let vid = vault_id(dir);
    assert_ok(&set_policy(dir, &policy_json(&vid), &[]), "initial set");

    // Tamper: flip one byte in the sealed policy -> AuthFail, exit 2.
    let sealed_path = dir.join("v.geode/policy.json.sealed");
    let original = std::fs::read(&sealed_path).expect("sealed bytes");
    let mut tampered = original.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    std::fs::write(&sealed_path, &tampered).expect("tamper");
    let show = geode(dir, &["--key", "k.gkey", "policy", "show", "v.geode"]);
    assert_eq!(
        show.status.code(),
        Some(2),
        "tampered policy: {}",
        String::from_utf8_lossy(&show.stderr)
    );
    std::fs::write(&sealed_path, &original).expect("restore");
    assert_ok(
        &geode(dir, &["--key", "k.gkey", "policy", "show", "v.geode"]),
        "show after restore",
    );

    // vault_id mismatch: usage error, exit 1 (fail closed on set).
    let wrong = policy_json("00112233445566778899aabbccddeeff");
    let mismatch = set_policy(dir, &wrong, &["--yes", "--break-glass"]);
    assert_eq!(
        mismatch.status.code(),
        Some(1),
        "vault_id mismatch: {}",
        String::from_utf8_lossy(&mismatch.stderr)
    );
}

#[test]
fn token_issue_policy_less_denies() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup_vault(dir);
    // No policy sealed: the default policy grants `human:local` admin on
    // `""` and denies everyone else (10-policy 3), so an agent grant MUST
    // fail closed — issue_narrow over the default policy, exit 3.
    let issue = geode(
        dir,
        &[
            "--key",
            "k.gkey",
            "agent",
            "token",
            "issue",
            "--vault",
            "v.geode",
            "--principal",
            "agent:oma",
            "--ops",
            "list,read",
            "--allow-prefix",
            "scratch/",
            "--ttl",
            "15m",
        ],
    );
    assert_eq!(
        issue.status.code(),
        Some(3),
        "policy-less agent grant must deny: {}",
        String::from_utf8_lossy(&issue.stderr)
    );
}

#[test]
fn token_issue_narrows_policy() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup_vault(dir);
    let vid = vault_id(dir);
    assert_ok(&set_policy(dir, &policy_json(&vid), &[]), "initial set");

    // Token issue narrows policy (10-policy 2.5): a grant the policy
    // would deny (write on scratch/) exits 3.
    let widen = geode(
        dir,
        &[
            "--key",
            "k.gkey",
            "agent",
            "token",
            "issue",
            "--vault",
            "v.geode",
            "--principal",
            "agent:oma",
            "--ops",
            "list,read,write",
            "--allow-prefix",
            "scratch/",
            "--ttl",
            "15m",
        ],
    );
    assert_eq!(
        widen.status.code(),
        Some(3),
        "widening token: {}",
        String::from_utf8_lossy(&widen.stderr)
    );

    // A principal absent from policy cannot issue at all (exit 3).
    let nobody = geode(
        dir,
        &[
            "--key",
            "k.gkey",
            "agent",
            "token",
            "issue",
            "--vault",
            "v.geode",
            "--principal",
            "agent:nobody",
            "--ops",
            "list",
            "--allow-prefix",
            "scratch/",
            "--ttl",
            "15m",
        ],
    );
    assert_eq!(nobody.status.code(), Some(3));

    // A narrowing token issues fine. Note `--max-bytes`: the CLI default
    // (1 MiB) would exceed the grant's 64 KiB cap and deny — a security
    // parameter is never silently clamped, so the operator passes it.
    let narrow = geode(
        dir,
        &[
            "--key",
            "k.gkey",
            "--output",
            "json",
            "agent",
            "token",
            "issue",
            "--vault",
            "v.geode",
            "--principal",
            "agent:oma",
            "--ops",
            "list,read",
            "--allow-prefix",
            "scratch/",
            "--ttl",
            "15m",
            "--max-bytes",
            "65536",
        ],
    );
    assert_ok(&narrow, "narrowing token issue");
    let doc: serde_json::Value = serde_json::from_slice(&narrow.stdout).expect("issue json");
    assert!(doc["token"].as_str().is_some_and(|t| !t.is_empty()));
}
