//! Hash manifest ft_* path: static-key RC4 over a binary manifest.

use crate::crypto::{hex::to_hex, rc4, sha1};
use crate::error::{Error, Result};
use obfstr::obfstr;
use std::fmt::Write as _;
use std::sync::OnceLock;

pub const HASH_MANIFEST_KEY_SEED: [u8; 24] = [
    0x91, 0x12, 0x24, 0xf2, 0xe9, 0xe2, 0x91, 0x12, 0x24, 0xf2, 0xf8, 0xe2, 0x91, 0x12, 0x24, 0xf2,
    0xe9, 0xe2, 0x91, 0x12, 0x24, 0xf2, 0xe9, 0xe2,
];

static KEY: OnceLock<[u8; 20]> = OnceLock::new();

pub fn hash_manifest_key() -> [u8; 20] {
    *KEY.get_or_init(|| sha1::digest(&HASH_MANIFEST_KEY_SEED))
}

pub fn is_hash_manifest_name(file_name: &str) -> bool {
    let prefix = obfstr!("ft_").to_owned();
    // get(), not slicing: byte 3 can split a multibyte char ("a€x.dat").
    file_name.get(..prefix.len()).is_some_and(|head| head.eq_ignore_ascii_case(&prefix))
}

#[derive(Debug, Clone)]
pub struct Record {
    pub id: u32,
    pub kind: u32,
    pub path: String,
    pub flags: u32,
    pub digests: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct Manifest {
    pub records: Vec<Record>,
}

const MIN_RECORD_SIZE: usize = 20;

struct Cursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.offset
    }

    fn read_bytes(&mut self, count: usize, field: &'static str) -> Result<&'a [u8]> {
        let end = self.offset.checked_add(count).ok_or(Error::ManifestEof { what: field })?;
        let slice = self.data.get(self.offset..end).ok_or(Error::ManifestEof { what: field })?;
        self.offset = end;
        Ok(slice)
    }

    fn read_u32_le(&mut self, field: &'static str) -> Result<u32> {
        let bytes = self.read_bytes(4, field)?;
        let array: [u8; 4] = bytes.try_into().map_err(|_| Error::ManifestEof { what: field })?;
        Ok(u32::from_le_bytes(array))
    }

    fn read_u16_le(&mut self, field: &'static str) -> Result<u16> {
        let bytes = self.read_bytes(2, field)?;
        let array: [u8; 2] = bytes.try_into().map_err(|_| Error::ManifestEof { what: field })?;
        Ok(u16::from_le_bytes(array))
    }
}

pub fn parse_manifest_binary(data: &[u8]) -> Result<Manifest> {
    let mut cursor = Cursor::new(data);
    let file_count = cursor.read_u32_le("file count")? as usize;
    if file_count.saturating_mul(MIN_RECORD_SIZE) > data.len() {
        return Err(Error::ManifestFileCount);
    }
    let mut records = Vec::with_capacity(file_count);
    for _ in 0..file_count {
        let id = cursor.read_u32_le("record id")?;
        let kind = cursor.read_u32_le("record kind")?;
        let path_length = cursor.read_u32_le("path length")? as usize;
        if path_length > cursor.remaining() {
            return Err(Error::ManifestPathLength);
        }
        let path_bytes = cursor.read_bytes(path_length, "path")?;
        let path = String::from_utf8_lossy(path_bytes).into_owned();
        let flags = cursor.read_u32_le("flags")?;
        let digest_count = cursor.read_u32_le("digest count")? as usize;
        if digest_count.saturating_mul(2) > cursor.remaining() {
            return Err(Error::ManifestDigestCount);
        }
        let mut digests = Vec::with_capacity(digest_count);
        for _ in 0..digest_count {
            let length = cursor.read_u16_le("digest length")? as usize;
            digests.push(cursor.read_bytes(length, "digest")?.to_vec());
        }
        records.push(Record { id, kind, path, flags, digests });
    }
    if cursor.remaining() != 0 {
        return Err(Error::ManifestTrailing { parsed: cursor.offset, total: data.len() });
    }
    Ok(Manifest { records })
}

pub fn render_manifest_text(manifest: &Manifest) -> String {
    let mut text = String::new();
    let _ = writeln!(text, "files: {}", manifest.records.len());
    for record in &manifest.records {
        let _ = writeln!(
            text,
            "id={} kind={} flags={} path={}",
            record.id, record.kind, record.flags, record.path
        );
        for digest in &record.digests {
            let _ = writeln!(text, "    {}", to_hex(digest));
        }
    }
    text
}

pub fn decrypt_manifest_text(file_bytes: &[u8]) -> Result<String> {
    let plain = rc4::crypt(file_bytes, &hash_manifest_key());
    let manifest = parse_manifest_binary(&plain)?;
    Ok(render_manifest_text(&manifest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_matches_the_known_constant() {
        assert_eq!(
            hash_manifest_key(),
            [
                0x10, 0x30, 0xab, 0xed, 0x06, 0x5a, 0x2f, 0xaf, 0xe7, 0x1c, 0x6b, 0x83, 0x6d, 0xbb,
                0x28, 0x35, 0x6e, 0x0c, 0x62, 0x54
            ]
        );
    }

    #[test]
    fn recognises_prefix_case_insensitively() {
        assert!(is_hash_manifest_name("ft_1.dat"));
        assert!(is_hash_manifest_name("FT_99.dat"));
        assert!(!is_hash_manifest_name("armorgrp.dat"));
        assert!(!is_hash_manifest_name("ft"));
    }

    #[test]
    fn unicode_names_do_not_panic() {
        assert!(!is_hash_manifest_name("a€x.dat"));
        assert!(!is_hash_manifest_name("€ft_1.dat"));
        assert!(is_hash_manifest_name("ft_1223859.dat"));
    }

    fn build_manifest_binary() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&7u32.to_le_bytes());
        data.extend_from_slice(&2u32.to_le_bytes());
        let path = b"system/l2.exe";
        data.extend_from_slice(&(path.len() as u32).to_le_bytes());
        data.extend_from_slice(path);
        data.extend_from_slice(&5u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&[0xAB, 0xCD]);
        data
    }

    #[test]
    fn parses_a_well_formed_manifest() {
        let manifest = parse_manifest_binary(&build_manifest_binary()).unwrap();
        assert_eq!(manifest.records.len(), 1);
        assert_eq!(manifest.records[0].path, "system/l2.exe");
        assert_eq!(manifest.records[0].digests[0], vec![0xAB, 0xCD]);
    }

    #[test]
    fn round_trips_through_rc4() {
        let encrypted = rc4::crypt(&build_manifest_binary(), &hash_manifest_key());
        let text = decrypt_manifest_text(&encrypted).unwrap();
        assert!(text.contains("system/l2.exe"));
    }

    #[test]
    fn rejects_garbage_instead_of_allocating() {
        let garbage = vec![0xFFu8; 64];
        assert!(parse_manifest_binary(&garbage).is_err());
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut data = build_manifest_binary();
        data.push(0);
        assert!(parse_manifest_binary(&data).is_err());
    }
}
