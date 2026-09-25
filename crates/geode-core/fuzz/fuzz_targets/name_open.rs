#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data:&[u8]|{let nk=[0u8;32];let vid=geode_grotto::kdf::VaultId([0u8;16]);let _=geode_grotto::name::open_name_ciphertext(&nk,&vid,geode_grotto::kdf::Epoch(1),&[0u8;16],data);});
