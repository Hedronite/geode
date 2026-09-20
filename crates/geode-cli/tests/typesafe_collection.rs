//! Bundled `TypeSafe` remainder collection: well-formed, secret-free, shadow.

use std::path::PathBuf;

fn collection_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("docs")
        .join("examples")
        .join("typesafe")
        .join("opencollection.yml")
}

#[test]
fn typesafe_collection_is_shadow_secret_and_token_free() {
    let text = std::fs::read_to_string(collection_path()).expect("read collection");
    let doc: serde_yaml::Value = serde_yaml::from_str(&text).expect("yaml");
    assert_eq!(
        doc["info"]["name"].as_str(),
        Some("TypeSafe Jev (Geode remainder)")
    );
    assert!(text.contains("jevShadow"));
    assert!(text.contains("secret: true"));
    assert!(text.contains("typesafeApiKey"));
    assert!(text.contains("/v1/systemone"));
    assert!(text.contains("\"allow\""));
    assert!(text.contains("\"deny\""));
    assert!(text.contains("\"ask\""));
    assert!(!text.contains("GTOK"));
    assert!(!text.contains("sk-"));
    assert!(!text.contains("Bearer ts_"));
    let body = text.split("data: |-").nth(1).unwrap_or("");
    assert!(!body.contains("TYPESAFE_API_KEY"));
    assert!(!body.contains("GEODE_TOKEN"));
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("value:") {
            assert!(!t.contains(".gkey"), "literal key path: {t}");
        }
    }
}
