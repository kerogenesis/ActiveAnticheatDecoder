//! Scryde GamekitData header detection and decoding routines.

use crate::error::{Error, Result};
use cipher::KeyInit;
use flate2::read::ZlibDecoder;
use num_bigint::BigUint;
use obfstr::obfstr;
use std::fmt;
use std::io::Read;
use std::path::Path;

const GAMEKIT_HEADER: &[u8; 22] = b"G\0a\0m\0e\0k\0i\0t\0D\0a\0t\0a\0";
const LINEAGE2_HEADER: &[u8; 22] = b"L\0i\0n\0e\0a\0g\0e\x002\0V\0e\0r\0";

const KEY_211: [u8; 8] = [0x1E, 0x52, 0x46, 0xF9, 0x96, 0x10, 0xCD, 0x33];
const KEY_212: [u8; 8] = [0x42, 0xC1, 0x36, 0xE6, 0x6C, 0x1F, 0x68, 0xE6];

const RSA_MODULUS_KEY1: [u8; 128] = [
    0x39, 0x20, 0xae, 0x94, 0x60, 0xc6, 0xd4, 0x13, 0x64, 0xd2, 0x93, 0xaa, 0xa3, 0xc6, 0xa4, 0xc3,
    0x67, 0xae, 0x69, 0xd0, 0xb3, 0xc3, 0x67, 0xb5, 0xab, 0x81, 0x88, 0x10, 0xd2, 0xf1, 0x7a, 0x70,
    0xe3, 0x5d, 0x20, 0xae, 0x5b, 0xb6, 0x7b, 0xd8, 0x04, 0x56, 0xc8, 0x67, 0xc2, 0x29, 0x01, 0x07,
    0x19, 0x93, 0x30, 0x43, 0xfa, 0xed, 0x79, 0x46, 0x3e, 0x2f, 0xc0, 0xb1, 0x4e, 0x43, 0xd9, 0x1f,
    0xfd, 0x9b, 0xf6, 0x83, 0x0a, 0x89, 0xc0, 0x72, 0x7d, 0x5d, 0xc5, 0x95, 0x34, 0x32, 0x16, 0x8f,
    0xc1, 0xa5, 0xb1, 0x7b, 0xc8, 0x91, 0xce, 0xa1, 0x3d, 0x65, 0xb3, 0x88, 0x62, 0x44, 0x93, 0x55,
    0x63, 0x57, 0x87, 0x9b, 0xaf, 0x6d, 0x55, 0x89, 0xe2, 0xb1, 0xb8, 0x55, 0xfc, 0x09, 0x2e, 0x3d,
    0xf4, 0x69, 0x58, 0x12, 0xcf, 0x1a, 0x8a, 0x06, 0x44, 0x65, 0x01, 0x5c, 0xde, 0xd6, 0xb4, 0x75,
];

const RSA_MODULUS_KEY2: [u8; 128] = [
    0x83, 0x2d, 0xd7, 0x8f, 0x66, 0xc1, 0x3d, 0x12, 0x38, 0xdc, 0x89, 0x6a, 0xa8, 0xba, 0x51, 0x45,
    0x74, 0xc5, 0x9b, 0xd0, 0x11, 0x05, 0xd4, 0x14, 0x93, 0x74, 0xb6, 0x67, 0x78, 0x8f, 0xe6, 0x50,
    0xe4, 0x3c, 0x08, 0x29, 0xe3, 0x4b, 0x8d, 0xc0, 0xb7, 0x5e, 0xb4, 0xf2, 0x9e, 0x7d, 0xa6, 0xc9,
    0x02, 0x3a, 0x79, 0x81, 0x38, 0x63, 0x55, 0x86, 0x60, 0x03, 0x1d, 0xb7, 0xa0, 0xc0, 0x2c, 0xe7,
    0xbd, 0xd7, 0xb5, 0xe5, 0xdd, 0xd1, 0x3e, 0x4d, 0x27, 0xea, 0x6e, 0xbe, 0x03, 0x7d, 0x41, 0xb6,
    0x50, 0x88, 0xa1, 0x94, 0x73, 0x6e, 0xe4, 0x75, 0x01, 0xf9, 0x9e, 0xda, 0x2d, 0x29, 0x19, 0xfc,
    0x3c, 0x4c, 0x6e, 0x1c, 0xbc, 0x29, 0xe8, 0xd6, 0xe1, 0x8a, 0x8a, 0xa3, 0x61, 0x16, 0xef, 0x0f,
    0x2f, 0x17, 0x8d, 0x7e, 0xd1, 0x0c, 0x0a, 0xef, 0x37, 0xf7, 0xdd, 0x72, 0x84, 0x39, 0xdf, 0x97,
];

const MAGIC_121_VTX: [u8; 4] = [0xC1, 0x83, 0x2A, 0x9E];
const MAGIC_121_OGG: [u8; 4] = *b"OggS";
const MAGIC_121_L2SD: [u8; 4] = *b"L2SD";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatType {
    Ver111,
    Ver120,
    Ver121,
    Ver211,
    Ver212,
    Ver413,
    OggSL2SDBM,
}

impl fmt::Display for FormatType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ver111 => write!(f, "Ver111"),
            Self::Ver120 => write!(f, "Ver120"),
            Self::Ver121 => write!(f, "Ver121"),
            Self::Ver211 => write!(f, "Ver211"),
            Self::Ver212 => write!(f, "Ver212"),
            Self::Ver413 => write!(f, "Ver413"),
            Self::OggSL2SDBM => write!(f, "OggSL2SDBM"),
        }
    }
}

pub fn detect_format(data: &[u8]) -> Option<FormatType> {
    if data.len() < 28 {
        return None;
    }
    if data.starts_with(b"OggSL2SDBM") {
        return Some(FormatType::OggSL2SDBM);
    }
    if &data[0..22] == GAMEKIT_HEADER {
        match &data[22..28] {
            [b'1', 0, b'1', 0, b'1', 0] => Some(FormatType::Ver111),
            [b'1', 0, b'2', 0, b'0', 0] => Some(FormatType::Ver120),
            [b'1', 0, b'2', 0, b'1', 0] => Some(FormatType::Ver121),
            [b'2', 0, b'1', 0, b'1', 0] => Some(FormatType::Ver211),
            [b'2', 0, b'1', 0, b'2', 0] => Some(FormatType::Ver212),
            [b'4', 0, b'1', 0, b'3', 0] => Some(FormatType::Ver413),
            _ => None,
        }
    } else {
        None
    }
}

pub fn convert_to_lineage2(data: &[u8]) -> Option<Vec<u8>> {
    let _format = detect_format(data)?;
    let mut converted = data.to_vec();
    if converted.len() >= 22 && &converted[..22] == GAMEKIT_HEADER {
        converted[..22].copy_from_slice(LINEAGE2_HEADER);
    }
    Some(converted)
}

fn decrypt_111(payload: &[u8]) -> Vec<u8> {
    payload.iter().map(|&b| b ^ 0xAC).collect()
}

fn key_120_byte(i: usize) -> u8 {
    let a1 = (i + 230) as u32;
    let key_low = ((a1 ^ (a1 >> 8)) & 0x0F) as u8;
    let key_high = ((((a1 >> 4) ^ (a1 >> 12)) & 0x0F) << 4) as u8;
    key_low | key_high
}

fn decrypt_120(payload: &[u8]) -> Vec<u8> {
    payload
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key_120_byte(i))
        .collect()
}

fn key_121_from_filename(filename: &str) -> u8 {
    let sum: u32 = filename
        .bytes()
        .map(|b| b.to_ascii_lowercase() as u32)
        .sum();
    (sum & 0xFF) as u8
}

fn decrypt_121(payload: &[u8], filename: &str) -> Vec<u8> {
    let is_bmp = filename.to_ascii_lowercase().ends_with(".bmp");
    let found_key = (payload.len() >= 4)
        .then(|| {
            (0..=255u8).find(|&candidate| {
                let p0 = payload[0] ^ candidate;
                let p1 = payload[1] ^ candidate;
                let p2 = payload[2] ^ candidate;
                let p3 = payload[3] ^ candidate;
                [p0, p1, p2, p3] == MAGIC_121_VTX
                    || [p0, p1, p2, p3] == MAGIC_121_OGG
                    || [p0, p1, p2, p3] == MAGIC_121_L2SD
                    || (is_bmp && p0 == b'B' && p1 == b'M')
            })
        })
        .flatten();

    let key = found_key.unwrap_or_else(|| key_121_from_filename(filename));
    payload.iter().map(|&b| b ^ key).collect()
}

fn decrypt_211(payload: &[u8]) -> Vec<u8> {
    payload
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ KEY_211[i % 8])
        .collect()
}

fn decrypt_212(payload: &[u8]) -> Vec<u8> {
    payload
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ KEY_212[i % 8])
        .collect()
}

fn rsa_modpow_block(block: &[u8; 128], modulus: &BigUint, exponent: &BigUint) -> [u8; 128] {
    let base = BigUint::from_bytes_be(block);
    let result = base.modpow(exponent, modulus);
    let res_bytes = result.to_bytes_be();

    let mut out = [0u8; 128];
    if res_bytes.len() <= 128 {
        let offset = 128 - res_bytes.len();
        out[offset..].copy_from_slice(&res_bytes);
    }
    out
}

fn align_413_chunk_size(size: usize) -> usize {
    (size + 3) & !3
}

fn decoded_413_chunk_payload(block: &[u8; 128], chunk_size: usize) -> Option<&[u8]> {
    if chunk_size == 0 || chunk_size > 124 {
        return None;
    }
    let aligned_size = align_413_chunk_size(chunk_size);
    let start = 128usize.checked_sub(aligned_size)?;
    Some(&block[start..start + chunk_size])
}

fn decompress_413_payload(reconstructed_zlib: &[u8]) -> Option<Vec<u8>> {
    if reconstructed_zlib.len() <= 4 {
        return None;
    }
    let expected_size = u32::from_le_bytes([
        reconstructed_zlib[0],
        reconstructed_zlib[1],
        reconstructed_zlib[2],
        reconstructed_zlib[3],
    ]) as usize;

    let mut zlib_decoder = ZlibDecoder::new(&reconstructed_zlib[4..]);
    let mut decompressed = Vec::with_capacity(expected_size);
    if zlib_decoder.read_to_end(&mut decompressed).is_ok() && decompressed.len() == expected_size {
        Some(decompressed)
    } else {
        None
    }
}

fn decrypt_413(payload: &[u8]) -> Result<Vec<u8>> {
    if payload.is_empty() {
        return Err(Error::GamekitDecodeFailed);
    }
    if payload.len() >= 128 {
        let block_count = payload.len() / 128;
        if block_count > 0 {
            for &(exp, mod_key) in &[(29u32, &RSA_MODULUS_KEY1), (53u32, &RSA_MODULUS_KEY2)] {
                let mod_biguint = BigUint::from_bytes_le(mod_key);
                let exp_biguint = BigUint::from(exp);
                let mut reconstructed_zlib = Vec::with_capacity(block_count * 124);
                let mut ok = true;
                for idx in 0..block_count {
                    let chunk = &payload[idx * 128..(idx + 1) * 128];
                    let block_arr: &[u8; 128] = chunk.try_into().unwrap();
                    let decrypted_block = rsa_modpow_block(block_arr, &mod_biguint, &exp_biguint);
                    let chunk_size = u32::from_be_bytes([
                        decrypted_block[0],
                        decrypted_block[1],
                        decrypted_block[2],
                        decrypted_block[3],
                    ]) as usize;

                    let is_last = idx == block_count - 1;
                    if (!is_last && chunk_size != 124) || chunk_size > 124 {
                        ok = false;
                        break;
                    }
                    if chunk_size == 0 {
                        continue;
                    }

                    let Some(chunk_payload) =
                        decoded_413_chunk_payload(&decrypted_block, chunk_size)
                    else {
                        ok = false;
                        break;
                    };
                    reconstructed_zlib.extend_from_slice(chunk_payload);
                }

                if ok && let Some(decompressed) = decompress_413_payload(&reconstructed_zlib) {
                    return Ok(decompressed);
                }
            }
        }
    }

    let bf_keys: [&[u8; 8]; 2] = [
        &[0x59, 0x3B, 0x5D, 0x2C, 0x47, 0x74, 0x3D, 0x31],
        b"Lineage2",
    ];
    let aligned_len = payload.len() - (payload.len() % 8);
    if aligned_len >= 8 {
        let aligned_payload = &payload[..aligned_len];
        for bf_key in bf_keys {
            if let Ok(cipher) = blowfish::Blowfish::<byteorder::BE>::new_from_slice(bf_key) {
                let mut decrypted = aligned_payload.to_vec();
                for chunk in decrypted.chunks_exact_mut(8) {
                    let mut block = cipher::Block::<blowfish::Blowfish<byteorder::BE>>::default();
                    block.copy_from_slice(chunk);
                    cipher::BlockCipherDecrypt::decrypt_block(&cipher, &mut block);
                    chunk.copy_from_slice(&block);
                }

                if decrypted.len() >= 4 {
                    let expected_size =
                        u32::from_le_bytes(decrypted[..4].try_into().unwrap()) as usize;
                    let mut decompressor = flate2::Decompress::new(true);
                    let mut decompressed = Vec::with_capacity(expected_size);
                    if decompressor
                        .decompress_vec(
                            &decrypted[4..],
                            &mut decompressed,
                            flate2::FlushDecompress::None,
                        )
                        .is_ok()
                        && decompressed.len() == expected_size
                    {
                        return Ok(decompressed);
                    }
                }
            }
        }
    }

    Err(Error::GamekitDecodeFailed)
}

pub fn decode_if_gamekit(data: &[u8], path: &Path) -> Result<Option<(Vec<u8>, FormatType)>> {
    let Some(format) = detect_format(data) else {
        return Ok(None);
    };
    if data.len() < 28 {
        return Ok(None);
    }
    let payload = &data[28..];
    let raw_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let filename = raw_name
        .strip_prefix(obfstr!("enc."))
        .or_else(|| raw_name.strip_prefix(obfstr!("dec.")))
        .unwrap_or(raw_name);

    let decoded = match format {
        FormatType::Ver111 => decrypt_111(payload),
        FormatType::Ver120 => decrypt_120(payload),
        FormatType::Ver121 => decrypt_121(payload, filename),
        FormatType::Ver211 => decrypt_211(payload),
        FormatType::Ver212 => decrypt_212(payload),
        FormatType::Ver413 => decrypt_413(payload)?,
        FormatType::OggSL2SDBM => payload.to_vec(),
    };

    Ok(Some((decoded, format)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_gamekit_header() {
        let mut data = Vec::new();
        data.extend_from_slice(GAMEKIT_HEADER);
        data.extend_from_slice(&[b'1', 0, b'1', 0, b'1', 0]);
        assert_eq!(detect_format(&data), Some(FormatType::Ver111));
    }

    #[test]
    fn decrypt_111_roundtrip() {
        let plain = b"Test 111 Payload";
        let encrypted: Vec<u8> = plain.iter().map(|&b| b ^ 0xAC).collect();
        let decrypted = decrypt_111(&encrypted);
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn converts_gamekit_header_to_lineage2() {
        let mut data = Vec::new();
        data.extend_from_slice(GAMEKIT_HEADER);
        data.extend_from_slice(&[b'1', 0, b'1', 0, b'1', 0]);
        data.extend_from_slice(&[0u8; 10]);

        let converted = convert_to_lineage2(&data).unwrap();
        assert_eq!(&converted[..22], LINEAGE2_HEADER);
        assert_eq!(&converted[22..28], &[b'1', 0, b'1', 0, b'1', 0]);
    }
}
