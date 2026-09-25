//! TUI UX — opaque help overlay + real operator verbs on a vault.
//!
//! Builds a nested vault with the `geode` CLI (fixture only), then drives
//! `geode_tui::keys::handle_key` and `geode_tui::draw::draw` **in-process**.
//! Empty picker is not success: every verb test opens a real vault.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use geode_tui::app::{App, Pane, SnapshotUi, VerifyState, View};
use geode_tui::keys::handle_key;
use geode_tui::theme::{Appearance, Palette};
use geode_tui::RunOptions;
use ratatui::backend::TestBackend;
use ratatui::Terminal;

fn geode_bin() -> PathBuf {
    for key in ["CARGO_BIN_EXE_GEO_DE", "CARGO_BIN_EXE_geode"] {
        if let Ok(p) = std::env::var(key) {
            return PathBuf::from(p);
        }
    }
    PathBuf::from(format!(
        "{}/../../target/debug/geode",
        env!("CARGO_MANIFEST_DIR")
    ))
}

struct Fixture {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    key: PathBuf,
    vault: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().to_path_buf();
        let key = root.join("id.gkey");
        let vault = root.join("notes.geode");
        Self {
            _tmp: tmp,
            root,
            key,
            vault,
        }
    }

    fn build(&self) {
        let k = Command::new(geode_bin())
            .args(["keygen"])
            .arg(&self.key)
            .output()
            .expect("keygen");
        assert!(
            k.status.success(),
            "keygen failed: {}",
            String::from_utf8_lossy(&k.stderr)
        );
        let init = Command::new(geode_bin())
            .args(["vault", "init"])
            .arg(&self.vault)
            .arg("--key")
            .arg(&self.key)
            .output()
            .expect("vault init");
        assert!(
            init.status.success(),
            "vault init failed: {}",
            String::from_utf8_lossy(&init.stderr)
        );
        let src_dir = self.root.join("src");
        fs::create_dir_all(src_dir.join("scratch")).expect("mkdir scratch");
        fs::create_dir_all(src_dir.join("notes")).expect("mkdir notes");
        fs::write(src_dir.join("hello.txt"), b"hello world\n").expect("write hello");
        fs::write(src_dir.join("scratch/plan.md"), b"# plan\n").expect("write plan");
        fs::write(src_dir.join("notes/readme.md"), b"readme\n").expect("write readme");
        let seal = Command::new(geode_bin())
            .args(["seal"])
            .arg(&src_dir)
            .arg(&self.vault)
            .arg("--key")
            .arg(&self.key)
            .output()
            .expect("seal");
        assert!(
            seal.status.success(),
            "seal failed: {}",
            String::from_utf8_lossy(&seal.stderr)
        );
    }
}

fn no_splash(appearance: Appearance) -> RunOptions {
    RunOptions {
        appearance,
        splash: false,
    }
}

fn open_app(fx: &Fixture, appearance: Appearance) -> App {
    let ctx = geode_tui::vault::open(&fx.vault, Some(&fx.key)).expect("open");
    App::with_options(
        Some(fx.vault.clone()),
        Some(fx.key.clone()),
        Some(ctx),
        no_splash(appearance),
    )
}

fn press(app: &mut App, code: KeyCode) {
    let _ = handle_key(app, KeyEvent::new(code, KeyModifiers::NONE));
}

fn press_char(app: &mut App, c: char) {
    press(app, KeyCode::Char(c));
}

fn buf_string(buf: &ratatui::buffer::Buffer) -> String {
    let area = buf.area();
    let mut s = String::new();
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            s.push_str(buf[(x, y)].symbol());
        }
        s.push('\n');
    }
    s
}

fn draw(app: &App, w: u16, h: u16) -> (String, ratatui::buffer::Buffer) {
    let backend = TestBackend::new(w, h);
    let mut term = Terminal::new(backend).expect("terminal");
    term.draw(|f| geode_tui::draw::draw(f, app)).expect("draw");
    let buf = term.backend().buffer().clone();
    (buf_string(&buf), buf)
}

#[test]
fn help_overlay_is_opaque() {
    let fx = Fixture::new();
    fx.build();
    let mut app = open_app(&fx, Appearance::Porcelain);
    press_char(&mut app, '?');
    assert!(app.help(), "help overlay should open on ?");

    let (rendered, buf) = draw(&app, 80, 36);
    assert!(rendered.contains("help"), "help title missing: {rendered}");
    assert!(
        rendered.contains("Geode TUI"),
        "help body missing: {rendered}"
    );
    assert!(
        rendered.contains("leakage honesty"),
        "help leakage-honesty line missing: {rendered}"
    );

    let want_bg = Palette::porcelain().bg;
    let mut opaque = 0u32;
    let mut overlay = String::new();
    let area = buf.area();
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            let cell = &buf[(x, y)];
            if cell.bg == want_bg {
                opaque += 1;
                overlay.push_str(cell.symbol());
            }
        }
        overlay.push('\n');
    }
    assert!(
        opaque > 80,
        "help overlay should fill with porcelain bg, opaque={opaque}"
    );
    assert!(
        overlay.contains("Geode TUI"),
        "opaque cells should carry help text: {overlay}"
    );
    assert!(
        !overlay.contains("hello.txt"),
        "tree text showed through opaque help: {overlay}"
    );
    assert!(
        !overlay.contains("object_id"),
        "meta text showed through opaque help: {overlay}"
    );
}

#[test]
fn operator_verbs_on_a_real_vault() {
    let fx = Fixture::new();
    fx.build();
    let mut app = open_app(&fx, Appearance::Graphite);
    assert!(!app.picker(), "unlocked vault is not the picker");
    assert!(
        app.row_count() >= 3,
        "nested fixture should paint a tree, got {}",
        app.row_count()
    );
    assert_eq!(app.pane(), Pane::Tree);
    assert_eq!(app.view(), View::Tree);
    assert_eq!(app.focus(), 0);

    press_char(&mut app, 'j');
    assert_eq!(app.focus(), 1, "j moves down");
    press_char(&mut app, 'k');
    assert_eq!(app.focus(), 0, "k moves up");

    press(&mut app, KeyCode::Tab);
    assert_eq!(app.pane(), Pane::Meta, "Tab focuses meta");
    press(&mut app, KeyCode::Tab);
    assert_eq!(
        app.pane(),
        Pane::Tree,
        "Tab skips closed preview and returns to tree"
    );

    press_char(&mut app, 'v');
    assert!(app.verify_overlay(), "v opens verify overlay");
    assert!(
        matches!(app.verify_state(), VerifyState::Ok { report, .. } if report.mode == "cheap"),
        "cheap verify should succeed"
    );
    press(&mut app, KeyCode::Esc);
    assert!(!app.verify_overlay(), "Esc closes verify overlay");

    // Land on a file row so preview has an object.
    let mut hops = 0;
    while app.focused_entry().is_none() && hops < 16 {
        press_char(&mut app, 'j');
        hops += 1;
    }
    assert!(
        app.focused_entry().is_some(),
        "should be able to j onto a file"
    );
    press_char(&mut app, 'p');
    assert!(app.preview().is_some(), "p opens bounded preview");
    assert_eq!(app.pane(), Pane::Preview);
    press(&mut app, KeyCode::Esc);
    assert!(app.preview().is_none(), "Esc closes preview");

    press_char(&mut app, 'L');
    assert!(app.picker(), "L returns to picker");
    assert!(
        !app.picker_items().is_empty(),
        "picker lists the locked vault"
    );
    press(&mut app, KeyCode::Enter);
    assert!(!app.picker(), "Enter re-opens the vault in-process");
    assert!(app.row_count() >= 3, "re-open restores the tree");
}

#[test]
fn list_view_is_flat_files() {
    let fx = Fixture::new();
    fx.build();
    let mut app = open_app(&fx, Appearance::Graphite);
    let tree_rows = app.row_count();
    // geode, keygen, vault, seal, open, verify, list
    for _ in 0..6 {
        press_char(&mut app, ']');
    }
    assert_eq!(app.view(), View::List, "six ] land on list");
    assert_eq!(
        app.row_count(),
        3,
        "list is three files, tree was {tree_rows}"
    );
    assert!(
        app.rows().iter().all(|r| !r.is_dir),
        "list view has no directory rows"
    );
    let (rendered, _) = draw(&app, 100, 24);
    assert!(
        rendered.contains("vault list") || rendered.contains("hello.txt"),
        "list pane should paint files: {rendered}"
    );
}

#[test]
fn help_jk_scrolls() {
    let fx = Fixture::new();
    fx.build();
    let mut app = open_app(&fx, Appearance::Graphite);
    press_char(&mut app, '?');
    assert_eq!(app.help_scroll(), 0);
    press_char(&mut app, 'j');
    assert_eq!(app.help_scroll(), 1);
    press_char(&mut app, 'k');
    assert_eq!(app.help_scroll(), 0);
}

#[test]
fn tree_hl_collapse_expand() {
    let fx = Fixture::new();
    fx.build();
    let mut app = open_app(&fx, Appearance::Graphite);
    let start = app.row_count();
    assert!(start >= 5, "expanded tree has dirs + files, got {start}");

    // Focus a directory row and collapse it.
    let mut hops = 0;
    while app.focused_row().is_none_or(|r| !r.is_dir) && hops < 16 {
        press_char(&mut app, 'j');
        hops += 1;
    }
    assert!(
        app.focused_row().is_some_and(|r| r.is_dir),
        "should find a directory row"
    );
    press_char(&mut app, 'h');
    assert!(
        app.row_count() < start,
        "h collapses a dir ({start} -> {})",
        app.row_count()
    );
    press_char(&mut app, 'l');
    assert_eq!(app.row_count(), start, "l re-expands the dir");
}

#[test]
fn castle_notes_geode_opens_when_present() {
    let Some(home) = std::env::var_os("HOME") else {
        return;
    };
    let vault = PathBuf::from(home).join("notes.geode");
    if !vault.join("GEODE").is_file() {
        return;
    }
    let ctx =
        geode_tui::vault::open(&vault, None).expect("open ~/notes.geode with XDG default.gkey");
    assert!(!ctx.is_locked());
    let cheap = geode_tui::vault::verify(&ctx, false).expect("cheap verify castle vault");
    assert!(cheap.chunks_checked >= 1 || cheap.files == 0);
    let mut app = App::with_options(
        Some(vault),
        None,
        Some(ctx),
        no_splash(Appearance::Graphite),
    );
    assert!(!app.picker());
    press_char(&mut app, 'j');
    press_char(&mut app, 'v');
    assert!(app.verify_overlay());
    press(&mut app, KeyCode::Esc);
    press_char(&mut app, 'L');
    assert!(app.picker());
}

#[test]
fn splash_header_is_0_2_0_not_0_1_1() {
    let backend = TestBackend::new(80, 24);
    let mut term = Terminal::new(backend).expect("terminal");
    let palette = Palette::graphite();
    term.draw(|f| geode_tui::splash::render(f, f.area(), &palette))
        .expect("splash");
    let rendered = buf_string(term.backend().buffer());
    assert!(
        rendered.contains(env!("CARGO_PKG_VERSION")),
        "splash missing version: {rendered}"
    );
    assert!(
        !rendered.contains("0.1.1"),
        "splash must not ship mock 0.1.1: {rendered}"
    );
    assert!(
        rendered.contains("GDE1") && rendered.contains("core"),
        "splash missing GDE1 · core: {rendered}"
    );
    assert!(
        rendered.contains("sealed")
            && rendered.contains("keyring default")
            && rendered.contains("exit 0"),
        "splash missing brandmark footer: {rendered}"
    );
}

#[test]
fn snapshot_pane_lists_creates_confirms_restore_on_core_types() {
    let fx = Fixture::new();
    fx.build();
    let mut app = open_app(&fx, Appearance::Graphite);
    press_char(&mut app, 's');
    assert!(app.snapshot_overlay(), "s opens snapshot overlay");
    assert!(app.snapshot_rows().is_empty(), "new vault has no snapshots");

    press_char(&mut app, 'n');
    assert!(
        matches!(app.snapshot_ui(), SnapshotUi::Name { .. }),
        "n starts name entry"
    );
    for c in "pre-edit".chars() {
        press_char(&mut app, c);
    }
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.snapshot_rows().len(), 1, "create lands a core snapshot");
    assert_eq!(app.snapshot_rows()[0].name, "pre-edit");
    assert_eq!(app.snapshot_rows()[0].epoch, 1);

    press_char(&mut app, 'r');
    match app.snapshot_ui() {
        SnapshotUi::ConfirmRestore { name, epoch } => {
            assert_eq!(name, "pre-edit");
            assert_eq!(*epoch, 1, "confirm MUST name snapshot and epoch");
        }
        other => panic!("expected confirm restore, got {other:?}"),
    }
    press_char(&mut app, 'y');
    assert!(
        matches!(app.snapshot_ui(), SnapshotUi::List),
        "y restores and returns to list"
    );
    assert!(!app.picker(), "restore keeps the vault open");

    let env = &app.snapshot_rows()[0];
    assert!(!env.vault_id.is_empty(), "core envelope has vault_id");
    assert!(
        !env.snapshot_mac.is_empty(),
        "core envelope has snapshot_mac"
    );
    assert!(env.manifest.is_object(), "core envelope carries manifest");

    let (rendered, buf) = draw(&app, 80, 32);
    assert!(
        rendered.contains("pre-edit"),
        "snapshot pane paints the core name: {rendered}"
    );
    assert!(
        rendered.contains("snapshot_mac") && rendered.contains(&env.snapshot_mac),
        "must paint core snapshot_mac: {rendered}"
    );
    assert!(
        rendered.contains("vault_id") && rendered.contains(&env.vault_id),
        "must paint core vault_id: {rendered}"
    );
    assert!(
        rendered.contains("manifest"),
        "must paint core manifest summary: {rendered}"
    );

    press_char(&mut app, 'g');
    match app.snapshot_ui() {
        SnapshotUi::ConfirmGc { preview } => {
            assert!(
                preview.kept >= 1 || preview.dropped == 0,
                "gc_preview reports live objects"
            );
        }
        other => panic!("g must call gc_preview, got {other:?}"),
    }
    let (preview_txt, _) = draw(&app, 80, 28);
    assert!(
        preview_txt.contains("gc_preview") && preview_txt.contains("kept"),
        "preview paints dropped/kept: {preview_txt}"
    );
    press_char(&mut app, 'y');
    match app.snapshot_ui() {
        SnapshotUi::GcDone { report } => {
            assert!(report.kept >= 1 || report.dropped == 0);
        }
        other => panic!("expected GcReport overlay after y, got {other:?}"),
    }
    let want_bg = Palette::graphite().bg;
    let mut opaque = 0u32;
    let area = buf.area();
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            if buf[(x, y)].bg == want_bg {
                opaque += 1;
            }
        }
    }
    assert!(
        opaque > 40,
        "snapshot overlay must be opaque, opaque={opaque}"
    );
}

#[test]
fn help_stays_opaque_over_snapshot_pane() {
    let fx = Fixture::new();
    fx.build();
    let mut app = open_app(&fx, Appearance::Porcelain);
    press_char(&mut app, 's');
    press_char(&mut app, '?');
    assert!(app.help());
    let (rendered, buf) = draw(&app, 80, 36);
    assert!(rendered.contains("Geode TUI"));
    assert!(!rendered.to_ascii_lowercase().contains("gtok"));
    assert!(!rendered.to_ascii_lowercase().contains("jev"));
    let want_bg = Palette::porcelain().bg;
    let mut overlay = String::new();
    let mut opaque = 0u32;
    let area = buf.area();
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            let cell = &buf[(x, y)];
            if cell.bg == want_bg {
                opaque += 1;
                overlay.push_str(cell.symbol());
            }
        }
        overlay.push('\n');
    }
    assert!(
        opaque > 80,
        "help still opaque over snapshots, opaque={opaque}"
    );
    assert!(
        !overlay.contains("hello.txt"),
        "tree leaked through help+snapshot: {overlay}"
    );
}
