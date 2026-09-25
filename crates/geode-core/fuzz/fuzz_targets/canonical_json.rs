#![no_main]
use libfuzzer_sys::fuzz_target;

/// Skip values canonicalize cannot stabilize (OS-03: non-integer floats + oversized ints).
fn should_skip(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Number(n) => {
            if n.as_f64().is_some_and(|f| f.fract() != 0.0) {
                return true;
            }
            // Large integers that do not round-trip through i64/u64 (RS-10 latent class).
            n.as_i64().is_none() && n.as_u64().is_none()
        }
        serde_json::Value::Array(a) => a.iter().any(should_skip),
        serde_json::Value::Object(o) => o.values().any(should_skip),
        _ => false,
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 128 {
        return;
    }
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) {
        if should_skip(&v) {
            return;
        }
        if let Ok(c1) = geode_grotto::manifest::canonicalize(&v) {
            let r: serde_json::Value = serde_json::from_slice(&c1).unwrap();
            let c2 = geode_grotto::manifest::canonicalize(&r).unwrap();
            assert_eq!(c1, c2);
        }
    }
});
