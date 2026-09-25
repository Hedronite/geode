#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data:&[u8]|{if let Ok(h)=geode_grotto::object::ObjectHeader::from_bytes(data){let a=geode_grotto::object::ObjectHeader::from_bytes(&h.to_bytes()).unwrap();assert_eq!(a.fields_bytes(),h.fields_bytes());}});
