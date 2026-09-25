#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data:&[u8]|{let ek=geode_grotto::kdf::EpochKey::from_bytes([0u8;32]);if let Ok(t)=geode_grotto::token::inspect(data,&ek,0){panic!("{t:?}");}});
