pub mod aac;
pub mod decode;
pub mod gamekit;
pub mod manifest;

pub use aac::{
    Decoded, MAGIC, PAYLOAD_OFFSET, RSA_BLOCK_LEN, RSA_BLOCK_OFFSET, RsaProfile, decode_any,
    decode_with_profile, header_is_aac, is_aac_container, parse_rsa_log,
};
pub use gamekit::{FormatType, convert_to_lineage2, detect_format};
pub use manifest::{
    HASH_MANIFEST_KEY_SEED, Manifest, Record, decode, format, hash_manifest_key,
    is_hash_manifest_name, parse,
};
