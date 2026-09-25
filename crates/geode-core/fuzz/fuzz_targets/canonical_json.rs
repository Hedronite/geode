#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data:&[u8]|{if let Ok(v)=serde_json::from_slice::<serde_json::Value>(data){if let Ok(o)=geode_grotto::manifest::canonicalize(&v){let p:serde_json::Value=serde_json::from_slice(&o).unwrap();assert_eq!(geode_grotto::manifest::canonicalize(&p).unwrap(),o);}}});
