pub mod aac;
pub mod gamekit;
pub mod manifest;
pub mod pipeline;

pub use aac::{
    Decoded, PAYLOAD_OFFSET, RSA_BLOCK_LEN, RSA_BLOCK_OFFSET, RsaProfile, header_is_aac,
    is_aac_container, parse_rsa_log, try_decrypt_with_keys,
};
pub use gamekit::{FormatType, detect_format, patch_to_lineage2};
pub use manifest::{
    HASH_MANIFEST_KEY_SEED, Manifest, Record, decrypt_manifest_text, hash_manifest_key,
    is_hash_manifest_name, parse_manifest_binary, render_manifest_text,
};
