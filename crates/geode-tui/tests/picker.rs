//! G4 (v311): honest verb tabs and multi-source vault picker discovery.

use std::path::{Path, PathBuf};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use geode_tui::app::{
    discover_picker_items, discover_picker_items_with, App, PickerItem, VERB_TABS,
};
use geode_tui::keys::handle_key;
use geode_tui::RunOptions;
use ratatui::backend::TestBackend;
use ratatui::Terminal;

struct Fixture {
    _t: tempfile::TempDir,
    root: PathBuf,
    cwd: PathBuf,
    home: PathBuf,
    xdg: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let t = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(t.path()).expect("canonicalize");
        let cwd = root.join("cwd");
        let home = root.join("home");
        let xdg = root.join("xdg");
        for d in [&cwd, &home, &xdg] {
            std::fs::create_dir_all(d).unwrap();
        }
        Self {
            _t: t,
            root,
            cwd,
            home,
            xdg,
        }
    }

    fn vault(&self, path: &Path) -> PathBuf {
        std::fs::create_dir_all(path).unwrap();
        std::fs::write(path.join("GEODE"), b"GDE1 vault\n").unwrap();
        path.to_path_buf()
    }

    fn registry(&self, lines: &[&str]) {
        let dir = self.xdg.join("hedronite/geode");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("vaults"), lines.join("\n")).unwrap();
    }
}

fn ids(items: &[PickerItem]) -> Vec<PathBuf> {
    items
        .iter()
        .map(|i| i.path.canonicalize().unwrap_or_else(|_| i.path.clone()))
        .collect()
}

fn canon(p: &Path) -> PathBuf {
    p.canonicalize().unwrap_or_else(|_| p.to_path_buf())
}

#[test]
fn discovers_all_sources_in_priority_order() {
    let f = Fixture::new();
    let explicit = f.vault(&f.cwd.join("explicit.geode"));
    let env = f.vault(&f.home.join("env.geode"));
    let reg_home = f.vault(&f.home.join("reg-a.geode"));
    let reg_abs = f.vault(&f.root.join("reg-b.geode"));
    let cwd_z = f.vault(&f.cwd.join("z.geode"));
    let cwd_a = f.vault(&f.cwd.join("a.geode"));
    let notes = f.vault(&f.home.join("notes.geode"));
    let non_vault = f.cwd.join("fake.geode");
    std::fs::create_dir_all(&non_vault).unwrap();
    let nested = f.cwd.join("nested.geode");
    std::fs::create_dir_all(nested.join("GEODE")).unwrap();
    f.registry(&[
        "# registry",
        "",
        "  ~/reg-a.geode  ",
        &reg_abs.display().to_string(),
        "missing.geode",
        "# tail",
    ]);

    let got = discover_picker_items_with(
        Some(Path::new("explicit.geode")),
        Some(&f.cwd),
        Some(&f.home),
        Some(&f.xdg),
        Some(Path::new("~/env.geode")),
    );
    assert_eq!(
        ids(&got),
        vec![
            canon(&explicit),
            canon(&env),
            canon(&reg_home),
            canon(&reg_abs),
            canon(&cwd_a),
            canon(&cwd_z),
            canon(&notes),
        ]
    );
}

#[cfg(unix)]
#[test]
fn canonical_dedup_keeps_highest_priority_position() {
    let f = Fixture::new();
    let source = f.vault(&f.root.join("source.geode"));
    std::os::unix::fs::symlink(&source, f.cwd.join("alias.geode")).unwrap();
    f.registry(&[
        &source.display().to_string(),
        &f.cwd.join("alias.geode").display().to_string(),
    ]);

    let got = discover_picker_items_with(
        Some(&source),
        Some(&f.cwd),
        Some(&f.home),
        Some(&f.xdg),
        Some(Path::new("alias.geode")),
    );
    assert_eq!(ids(&got), vec![canon(&source)]);
}

#[test]
fn non_vault_dirs_are_ignored() {
    let f = Fixture::new();
    let fake = f.cwd.join("fake.geode");
    std::fs::create_dir_all(&fake).unwrap();
    let marker_dir = f.cwd.join("marker-dir.geode");
    std::fs::create_dir_all(marker_dir.join("GEODE")).unwrap();
    f.registry(&[&fake.display().to_string()]);

    let got = discover_picker_items_with(
        Some(&fake),
        Some(&f.cwd),
        Some(&f.home),
        Some(&f.xdg),
        Some(&fake),
    );
    assert!(got.is_empty(), "{:?}", ids(&got));
}

#[test]
fn registry_falls_back_to_home_when_xdg_is_empty() {
    let f = Fixture::new();
    let vault = f.vault(&f.root.join("home-reg.geode"));
    let dir = f.home.join(".config/hedronite/geode");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("vaults"), format!("{}\n", vault.display())).unwrap();

    for xdg in [None, Some(Path::new(""))] {
        let got = discover_picker_items_with(None, Some(&f.cwd), Some(&f.home), xdg, None);
        assert_eq!(ids(&got), vec![canon(&vault)], "{xdg:?}");
    }
}

#[test]
fn missing_or_unreadable_registry_is_ignored() {
    let f = Fixture::new();
    let notes = f.vault(&f.home.join("notes.geode"));

    // Missing registry file: the home vault is still discovered.
    let got = discover_picker_items_with(None, Some(&f.cwd), Some(&f.home), Some(&f.xdg), None);
    assert_eq!(ids(&got), vec![canon(&notes)]);

    // Registry path is a directory: unreadable, skipped without panic.
    std::fs::create_dir_all(f.xdg.join("hedronite/geode/vaults")).unwrap();
    let got = discover_picker_items_with(None, Some(&f.cwd), Some(&f.home), Some(&f.xdg), None);
    assert_eq!(ids(&got), vec![canon(&notes)]);
}

#[test]
fn verb_tabs_are_interactive_only_and_cycle() {
    assert_eq!(VERB_TABS, &["geode", "list", "verify", "cat"]);
    for dead in ["keygen", "vault", "seal", "open", "keyring"] {
        assert!(!VERB_TABS.contains(&dead), "{dead} must not be a tab");
    }

    let mut app = App::with_options(None, None, None, RunOptions::default());
    let mut seen = Vec::new();
    for _ in 0..VERB_TABS.len() {
        seen.push(app.verb());
        if let Some(err) = app.error() {
            assert!(
                err.contains("unlock a vault first"),
                "dead banner/error: {err}"
            );
        }
        let _ = handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char(']'), KeyModifiers::NONE),
        );
    }
    seen.sort_unstable();
    assert_eq!(seen, (0..VERB_TABS.len()).collect::<Vec<_>>());
    assert_eq!(app.verb(), 0, "cycling wraps cleanly");
    for _ in 0..VERB_TABS.len() {
        let _ = handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('['), KeyModifiers::NONE),
        );
    }
    assert_eq!(app.verb(), 0, "reverse cycling wraps cleanly");
}

#[test]
fn help_documents_cli_verbs_outside_the_tabs() {
    let mut app = App::with_options(None, None, None, RunOptions::default());
    let _ = handle_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE),
    );
    assert!(app.help(), "help should open");
    let backend = TestBackend::new(100, 40);
    let mut term = Terminal::new(backend).expect("terminal");
    term.draw(|f| geode_tui::draw::draw(f, &app)).expect("draw");
    let buf = term.backend().buffer().clone();
    let mut text = String::new();
    for y in buf.area.top()..buf.area.bottom() {
        for x in buf.area.left()..buf.area.right() {
            text.push_str(buf[(x, y)].symbol());
        }
        text.push('\n');
    }
    assert!(text.contains("CLI verbs"), "{text}");
    assert!(text.contains("geode seal"), "{text}");
    assert!(text.contains("geode vault init"), "{text}");
    assert!(
        text.contains("geode open VAULT DIR   decrypt vault to a directory"),
        "{text}"
    );
    assert!(!text.contains("open a mount"), "{text}");
}

fn child_default_discovery_assertions() {
    let home = PathBuf::from(std::env::var_os("HOME").expect("HOME"));
    let cwd = std::env::current_dir().expect("cwd");
    let env_vault = PathBuf::from(std::env::var_os("GEODE_VAULT").expect("GEODE_VAULT"));
    let reg = home.join("reg.geode");
    let notes = home.join("notes.geode");
    let expected = vec![
        canon(&env_vault),
        canon(&reg),
        canon(&cwd.join("a.geode")),
        canon(&cwd.join("z.geode")),
        canon(&notes),
    ];
    let got = discover_picker_items(None);
    assert_eq!(ids(&got), expected);
}

#[test]
fn default_discovery_uses_geode_vault_and_cwd_in_a_child() {
    if std::env::var_os("GEODE_PICKER_CHILD").is_some() {
        child_default_discovery_assertions();
        return;
    }
    let f = Fixture::new();
    let env_vault = f.vault(&f.home.join("env-vault.geode"));
    let _ = f.vault(&f.home.join("reg.geode"));
    let _ = f.vault(&f.cwd.join("z.geode"));
    let _ = f.vault(&f.cwd.join("a.geode"));
    let _ = f.vault(&f.home.join("notes.geode"));
    let registry_dir = f.xdg.join("hedronite/geode");
    std::fs::create_dir_all(&registry_dir).unwrap();
    std::fs::write(
        registry_dir.join("vaults"),
        "# child registry\n\n~/reg.geode\n",
    )
    .unwrap();

    let out = std::process::Command::new(std::env::current_exe().expect("current_exe"))
        .args([
            "--exact",
            "default_discovery_uses_geode_vault_and_cwd_in_a_child",
            "--test-threads=1",
        ])
        .env("GEODE_PICKER_CHILD", "1")
        .env("GEODE_VAULT", &env_vault)
        .env("HOME", &f.home)
        .env("XDG_CONFIG_HOME", &f.xdg)
        .current_dir(&f.cwd)
        .output()
        .expect("spawn picker child");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "child failed\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("running 1 test"),
        "child did not run exactly one test: {stdout}"
    );
    assert!(
        stdout.contains("1 passed"),
        "child did not pass exactly one test: {stdout}"
    );
}

#[test]
fn default_discovery_delegates_to_testable_helper() {
    let f = Fixture::new();
    let explicit = f.vault(&f.cwd.join("explicit.geode"));
    let cwd = std::env::current_dir().ok();
    let home = std::env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);
    let xdg = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);
    let env_vault = std::env::var_os("GEODE_VAULT")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);
    let helper = discover_picker_items_with(
        Some(&explicit),
        cwd.as_deref(),
        home.as_deref(),
        xdg.as_deref(),
        env_vault.as_deref(),
    );
    let default = discover_picker_items(Some(&explicit));
    assert_eq!(ids(&helper), ids(&default));
}
