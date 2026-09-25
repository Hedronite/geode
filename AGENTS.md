# Agent standing orders (Rust-TOPS 1.0) — geode

Goal: correct, dense, fast Rust. MSRV 1.89 · edition 2021 · unsafe forbid.

Crates: geode-grotto = parser-codec (95/90). geode = binary-cli (+ fuse/agent service overlays).
geode_tui = binary-cli journeys + library-util floors on non-render modules.

Before stopping:
```text
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo deny check
cargo nextest run --workspace --all-features --profile ci
cargo test --doc --workspace
```

Feature `fuse` compiles in CI (`cargo check -p geode-cli --features fuse`).
Coverage/CRAP record-only until S-04. Mutation/fuzz = Phase R.
