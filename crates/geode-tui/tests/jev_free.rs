//! The operator TUI is a human surface: token-free and Jev-free.

use std::fs;
use std::path::Path;

fn walk_rs(dir: &Path, hits: &mut Vec<String>) {
    for entry in fs::read_dir(dir).expect("read tui src") {
        let entry = entry.expect("entry");
        let path = entry.path();
        if path.is_dir() {
            walk_rs(&path, hits);
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = fs::read_to_string(&path).expect("read rs");
        for (i, line) in text.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            if lower.contains("jev")
                || lower.contains("systemone")
                || lower.contains("typesafe")
                || lower.contains("geode_jev")
                || lower.contains("gtok")
            {
                hits.push(format!("{}:{}:{line}", path.display(), i + 1));
            }
        }
    }
}

#[test]
fn tui_sources_are_jev_free() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut hits = Vec::new();
    walk_rs(&src, &mut hits);
    assert!(
        hits.is_empty(),
        "TUI must stay Jev-free / token-free:\n{}",
        hits.join("\n")
    );
}
