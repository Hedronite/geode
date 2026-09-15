//! Visible vault tree / list rows (v0.2.0 TUI UX).
//!
//! Manifest entries are a flat path list. The tree pane groups them by
//! `/`-separated prefixes so `h`/`l` can expand and collapse. List mode
//! is the same entries in `geode list` order — no directories, no indent.
//! Paths and sizes are public metadata (14-tui §4); nothing here is a
//! secret.

#![cfg_attr(not(feature = "tui"), allow(dead_code))]

use std::collections::{BTreeMap, BTreeSet};

use geode_grotto::manifest::Entry;

/// One painted row in the tree or list pane.
#[derive(Debug, Clone)]
pub struct TreeRow {
    /// Indent level (0 = vault root).
    pub depth: u8,
    /// Last path component (file or directory name).
    pub label: String,
    /// Full vault-relative path (directory prefix or file path).
    pub path: String,
    /// Directory node (has children) vs file.
    pub is_dir: bool,
    /// Whether this directory is expanded (false for files).
    pub expanded: bool,
    /// Index into the manifest entry list, when this row is a file.
    pub entry_index: Option<usize>,
    /// Plaintext size from the manifest (0 for directories).
    pub plain_len: u64,
    /// Chunk count from the manifest (0 for directories).
    pub chunk_count: u32,
}

struct Node {
    children: BTreeMap<String, Node>,
    file: Option<usize>,
}

impl Node {
    fn new() -> Self {
        Self {
            children: BTreeMap::new(),
            file: None,
        }
    }
}

/// Directory prefixes that should start expanded (every parent of every file).
#[must_use]
pub fn all_dir_paths(entries: &[Entry]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for e in entries {
        if let Some((dir, _)) = e.path.rsplit_once('/') {
            let mut acc = String::new();
            for part in dir.split('/') {
                if part.is_empty() {
                    continue;
                }
                if !acc.is_empty() {
                    acc.push('/');
                }
                acc.push_str(part);
                out.insert(acc.clone());
            }
        }
    }
    out
}

/// Visible rows for the current view.
///
/// `list_mode` is a flat `geode list` (one row per file). Otherwise a
/// directory tree filtered by `expanded`.
#[must_use]
pub fn visible_rows(
    entries: &[Entry],
    expanded: &BTreeSet<String>,
    list_mode: bool,
) -> Vec<TreeRow> {
    if list_mode {
        return entries
            .iter()
            .enumerate()
            .map(|(i, e)| TreeRow {
                depth: 0,
                label: e.path.clone(),
                path: e.path.clone(),
                is_dir: false,
                expanded: false,
                entry_index: Some(i),
                plain_len: e.plain_len,
                chunk_count: e.chunk_count,
            })
            .collect();
    }

    let mut root = Node::new();
    for (i, e) in entries.iter().enumerate() {
        let parts: Vec<&str> = e.path.split('/').filter(|s| !s.is_empty()).collect();
        if parts.is_empty() {
            continue;
        }
        let mut node = &mut root;
        let last = parts.len() - 1;
        for (pi, part) in parts.iter().enumerate() {
            node = node
                .children
                .entry((*part).to_string())
                .or_insert_with(Node::new);
            if pi == last {
                node.file = Some(i);
            }
        }
    }

    let mut rows = Vec::with_capacity(entries.len());
    walk(&root, "", 0, expanded, entries, &mut rows);
    rows
}

fn walk(
    node: &Node,
    prefix: &str,
    depth: u8,
    expanded: &BTreeSet<String>,
    entries: &[Entry],
    rows: &mut Vec<TreeRow>,
) {
    for (name, child) in &node.children {
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        let is_dir = !child.children.is_empty();
        if is_dir {
            let is_expanded = expanded.contains(&path);
            rows.push(TreeRow {
                depth,
                label: name.clone(),
                path: path.clone(),
                is_dir: true,
                expanded: is_expanded,
                entry_index: child.file,
                plain_len: 0,
                chunk_count: 0,
            });
            if is_expanded {
                walk(
                    child,
                    &path,
                    depth.saturating_add(1),
                    expanded,
                    entries,
                    rows,
                );
            }
        } else if let Some(i) = child.file {
            let e = &entries[i];
            rows.push(TreeRow {
                depth,
                label: name.clone(),
                path,
                is_dir: false,
                expanded: false,
                entry_index: Some(i),
                plain_len: e.plain_len,
                chunk_count: e.chunk_count,
            });
        }
    }
}
