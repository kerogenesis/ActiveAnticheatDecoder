//! ActiveAnticheatCrypt container decoding.

use crate::crypto::bigint::{self, Big};
use crate::crypto::rc4;
use crate::error::{Error, Result};
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
    pub modulus: Big,
    pub private_exponent_be: Vec<u8>,
}

impl RsaProfile {
    pub fn from_le_components(source: &str, n_le: &[u8], d_le: &[u8]) -> Result<Self> {
        let modulus = bigint::from_le_bytes(n_le).ok_or(Error::ModulusTooLarge)?;
        if bigint::is_zero(&modulus) {
            return Err(Error::ModulusZero);
        }
        if modulus[0] % 2 == 0 {
            return Err(Error::ModulusZero);
        }
        let mut private_exponent_be = d_le.to_vec();
        private_exponent_be.reverse();
        Ok(Self {
            source: source.to_owned(),
            modulus,
            private_exponent_be,
        })
    }
}

fn hex_to_bytes(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || !text.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

fn find_component(text: &str, name: &str) -> Option<Vec<u8>> {
    let needle = format!("{name}{}", obfstr!("_LE="));
    let start = text.find(&needle)? + needle.len();
    let rest = &text[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_hexdigit())
        .unwrap_or(rest.len());
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

pub struct Decoded {
    pub plaintext: Vec<u8>,
}

pub fn decode_with_profile(file_bytes: &[u8], profile: &RsaProfile) -> Result<Decoded> {
    if !is_aac_container(file_bytes) {
        return Err(Error::NotAacContainer);
    }
    let ciphertext = &file_bytes[RSA_BLOCK_OFFSET..RSA_BLOCK_OFFSET + RSA_BLOCK_LEN];
    let value = bigint::from_be_bytes(ciphertext).ok_or(Error::CiphertextTooLarge)?;
    if bigint::greater_or_equal(&value, &profile.modulus) {
        return Err(Error::CiphertextOutOfRange);
    }
    let decrypted = bigint::mod_pow(&value, &profile.private_exponent_be, &profile.modulus);
    let block = bigint::to_be_bytes(&decrypted);
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
    let plaintext = rc4::crypt(&file_bytes[PAYLOAD_OFFSET..], &rc4_key);
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
        assert!(!bigint::is_zero(&profile.modulus));
    }

    #[test]
    fn components_and_log_agree() {
        let from_log = parse_rsa_log("N_LE=0100\nD_LE=0300\n", "log").unwrap();
        let from_mem = RsaProfile::from_le_components("mem", &[0x01, 0x00], &[0x03, 0x00]).unwrap();
        let log_modulus = bigint::to_be_bytes(&from_log.modulus);
        let mem_modulus = bigint::to_be_bytes(&from_mem.modulus);
        assert_eq!(from_log.private_exponent_be, from_mem.private_exponent_be);
        assert_eq!(log_modulus, mem_modulus);
    }

    #[test]
    fn zero_modulus_is_rejected() {
        assert!(RsaProfile::from_le_components("mem", &[0x00, 0x00], &[0x01]).is_err());
    }
}
