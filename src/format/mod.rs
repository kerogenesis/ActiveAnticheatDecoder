pub mod aac;
pub mod gamekit;
pub mod manifest;

pub use aac::{
    Decoded, MAGIC, PAYLOAD_OFFSET, RSA_BLOCK_LEN, RSA_BLOCK_OFFSET, RsaProfile, decode_any,
    decode_with_profile, header_is_aac, is_aac_container, parse_rsa_log,
};
pub use gamekit::{convert_to_lineage2, decode_if_gamekit};
pub use manifest::{KEY_SEED, Manifest, Record, decode, format, is_legacy_name, legacy_key, parse};
