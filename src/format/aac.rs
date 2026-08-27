//! ActiveAnticheatCrypt container decoding.

use crate::crypto::{hex::hex_to_bytes, rc4};
use crate::error::{Error, Result};
use num_bigint::BigUint;
use obfstr::{obfbytes, obfstr};

pub const MAGIC: &[u8; 20] = b"ActiveAnticheatCrypt";
pub const RSA_BLOCK_OFFSET: usize = 0x14;
pub const RSA_BLOCK_LEN: usize = 256;
pub const PAYLOAD_OFFSET: usize = 0x114;

pub fn header_is_aac(header: &[u8]) -> bool {
    let magic = obfbytes!(b"ActiveAnticheatCrypt");
    header.len() >= 20 && &header[..20] == magic
}

pub fn is_aac_container(bytes: &[u8]) -> bool {
    bytes.len() > PAYLOAD_OFFSET && header_is_aac(bytes)
}

#[derive(Clone)]
pub struct RsaProfile {
    pub source: String,
    pub modulus: BigUint,
    pub private_exponent_be: Vec<u8>,
}

impl RsaProfile {
    pub fn from_le_components(source: &str, n_le: &[u8], d_le: &[u8]) -> Result<Self> {
        let modulus = BigUint::from_bytes_le(n_le);
        if modulus.bits() == 0 || !modulus.bit(0) {
            return Err(Error::ModulusZero);
        }
        let mut private_exponent_be = d_le.to_vec();
        private_exponent_be.reverse();
        Ok(Self { source: source.to_owned(), modulus, private_exponent_be })
    }
}

fn find_component(text: &str, name: &str) -> Option<Vec<u8>> {
    let needle = format!("{name}{}", obfstr!("_LE="));
    let start = text.find(&needle)? + needle.len();
    let rest = &text[start..];
    let end = rest.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(rest.len());
    hex_to_bytes(&rest[..end])
}

pub fn parse_rsa_log(text: &str, source: &str) -> Result<RsaProfile> {
    let n_le =
        find_component(text, obfstr!("N")).ok_or(Error::MissingKeyComponent { name: "N_LE" })?;
    let d_le =
        find_component(text, obfstr!("D")).ok_or(Error::MissingKeyComponent { name: "D_LE" })?;
    RsaProfile::from_le_components(source, &n_le, &d_le)
}

fn pkcs1_v15_type2_unpad(block: &[u8]) -> Option<&[u8]> {
    if block.len() != RSA_BLOCK_LEN || block[0] != 0x00 || block[1] != 0x02 {
        return None;
    }
    let separator = block.iter().skip(2).position(|byte| *byte == 0x00)? + 2;
    if separator - 2 < 8 {
        return None;
    }
    Some(&block[separator + 1..])
}

/// Fixed-width big-endian encoding of a decrypted value.
///
/// num-bigint's `to_bytes_be` trims leading zeros, but PKCS#1 v1.5 parsing
/// requires the full RSA block width - without the zero padding every small
/// plaintext would be rejected at `block[0] != 0x00`.
fn fixed_be_block(value: &BigUint, width: usize) -> Vec<u8> {
    let trimmed = value.to_bytes_be();
    let mut block = vec![0u8; width];
    let copy_len = trimmed.len().min(width);
    block[width - copy_len..].copy_from_slice(&trimmed[trimmed.len() - copy_len..]);
    block
}

pub struct Decoded {
    pub plaintext: Vec<u8>,
}

pub fn decode_with_profile(file_bytes: &[u8], profile: &RsaProfile) -> Result<Decoded> {
    if !is_aac_container(file_bytes) {
        return Err(Error::NotAacContainer);
    }
    let ciphertext =
        BigUint::from_bytes_be(&file_bytes[RSA_BLOCK_OFFSET..RSA_BLOCK_OFFSET + RSA_BLOCK_LEN]);
    if ciphertext >= profile.modulus {
        return Err(Error::CiphertextOutOfRange);
    }
    let exponent = BigUint::from_bytes_be(&profile.private_exponent_be);
    let decrypted = ciphertext.modpow(&exponent, &profile.modulus);
    let block = fixed_be_block(&decrypted, RSA_BLOCK_LEN);
    let message = pkcs1_v15_type2_unpad(&block).ok_or(Error::Pkcs1PaddingInvalid)?;
    let magic = obfbytes!(b"ActiveAnticheatCrypt");
    let rc4_key: Vec<u8> = match message.len() {
        40 => {
            if &message[..20] != magic {
                return Err(Error::AacMagicMissing);
            }
            message[20..40].to_vec()
        }
        20 => message.to_vec(),
        other => return Err(Error::UnexpectedRsaMessageLen { got: other }),
    };
    let mut plaintext = file_bytes[PAYLOAD_OFFSET..].to_vec();
    rc4::crypt_in_place(&mut plaintext, &rc4_key);
    Ok(Decoded { plaintext })
}

pub fn decode_any(file_bytes: &[u8], profiles: &[RsaProfile]) -> Result<Decoded> {
    let mut reasons = Vec::new();
    for profile in profiles {
        match decode_with_profile(file_bytes, profile) {
            Ok(decoded) => return Ok(decoded),
            Err(error) => reasons.push(format!("{}: {error}", profile.source)),
        }
    }
    Err(Error::DecodeFailed { reasons })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_magic_from_header_only() {
        assert!(header_is_aac(MAGIC));
        assert!(!header_is_aac(b"not the right magic!"));
        assert!(!header_is_aac(b"short"));
    }

    #[test]
    fn unpad_rejects_short_padding() {
        let mut block = vec![0u8; RSA_BLOCK_LEN];
        block[1] = 0x02;
        block[5] = 0x00;
        assert!(pkcs1_v15_type2_unpad(&block).is_none());
    }

    #[test]
    fn parses_little_endian_components() {
        let text = "N_LE=0100\nD_LE=0300\n";
        let profile = parse_rsa_log(text, "test").unwrap();
        assert_eq!(profile.source, "test");
        assert_eq!(profile.private_exponent_be, vec![0x00, 0x03]);
        assert_ne!(profile.modulus, BigUint::default());
    }

    #[test]
    fn components_and_log_agree() {
        let from_log = parse_rsa_log("N_LE=0100\nD_LE=0300\n", "log").unwrap();
        let from_mem = RsaProfile::from_le_components("mem", &[0x01, 0x00], &[0x03, 0x00]).unwrap();
        assert_eq!(from_log.modulus, from_mem.modulus);
        assert_eq!(from_log.private_exponent_be, from_mem.private_exponent_be);
    }

    #[test]
    fn even_modulus_is_rejected() {
        // N_LE=0100 is odd; N_LE=0200 is even -> rejected with ModulusZero.
        assert!(RsaProfile::from_le_components("mem", &[0x02, 0x00], &[0x01]).is_err());
    }

    #[test]
    fn zero_modulus_is_rejected() {
        assert!(RsaProfile::from_le_components("mem", &[0x00, 0x00], &[0x01]).is_err());
    }

    #[test]
    fn fixed_block_pads_leading_zeros() {
        let value = BigUint::from(8u32);
        let block = fixed_be_block(&value, RSA_BLOCK_LEN);
        assert_eq!(block[RSA_BLOCK_LEN - 1], 8);
        assert!(block[..RSA_BLOCK_LEN - 1].iter().all(|&b| b == 0));
    }
}
