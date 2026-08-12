//! Legacy `ft_*` path: static-key RC4 over a binary manifest.

use crate::crypto::rc4;
use crate::crypto::sha1;
use crate::error::{Error, Result};
use obfstr::obfstr;
use std::fmt::Write as _;

pub const KEY_SEED: [u8; 24] = [
    0x91, 0x12, 0x24, 0xf2, 0xe9, 0xe2, 0x91, 0x12, 0x24, 0xf2, 0xf8, 0xe2, 0x91, 0x12, 0x24, 0xf2,
    0xe9, 0xe2, 0x91, 0x12, 0x24, 0xf2, 0xe9, 0xe2,
];

pub fn legacy_key() -> [u8; 20] {
    sha1::digest(&KEY_SEED)
}

pub fn is_legacy_name(file_name: &str) -> bool {
    let prefix = obfstr!("ft_").to_owned();
    file_name.len() >= prefix.len() && file_name[..prefix.len()].eq_ignore_ascii_case(&prefix)
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

    fn take(&mut self, count: usize, what: &'static str) -> Result<&'a [u8]> {
        if self.remaining() < count {
            return Err(Error::ManifestEof { what });
        }
        let slice = &self.data[self.offset..self.offset + count];
        self.offset += count;
        Ok(slice)
    }

    fn u32(&mut self, what: &'static str) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4, what)?.try_into().unwrap()))
    }

    fn u16(&mut self, what: &'static str) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2, what)?.try_into().unwrap()))
    }
}

pub fn parse(data: &[u8]) -> Result<Manifest> {
    let mut cursor = Cursor::new(data);
    let file_count = cursor.u32("file count")? as usize;
    if file_count.saturating_mul(MIN_RECORD_SIZE) > data.len() {
        return Err(Error::ManifestFileCount);
    }
    let mut records = Vec::with_capacity(file_count);
    for _ in 0..file_count {
        let id = cursor.u32("record id")?;
        let kind = cursor.u32("record kind")?;
        let path_length = cursor.u32("path length")? as usize;
        if path_length > cursor.remaining() {
            return Err(Error::ManifestPathLength);
        }
        let path_bytes = cursor.take(path_length, "path")?;
        let path = String::from_utf8_lossy(path_bytes).into_owned();
        let flags = cursor.u32("flags")?;
        let digest_count = cursor.u32("digest count")? as usize;
        if digest_count.saturating_mul(2) > cursor.remaining() {
            return Err(Error::ManifestDigestCount);
        }
        let mut digests = Vec::with_capacity(digest_count);
        for _ in 0..digest_count {
            let length = cursor.u16("digest length")? as usize;
            digests.push(cursor.take(length, "digest")?.to_vec());
        }
        records.push(Record {
            id,
            kind,
            path,
            flags,
            digests,
        });
    }
    if cursor.remaining() != 0 {
        return Err(Error::ManifestTrailing {
            parsed: cursor.offset,
            total: data.len(),
        });
    }
    Ok(Manifest { records })
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

pub fn format(manifest: &Manifest) -> String {
    let mut text = String::new();
    let _ = writeln!(text, "files: {}\n", manifest.records.len());
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

pub fn decode(file_bytes: &[u8]) -> Result<String> {
    let plain = rc4::crypt(file_bytes, &legacy_key());
    let manifest = parse(&plain)?;
    Ok(format(&manifest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_matches_the_known_constant() {
        assert_eq!(
            legacy_key(),
            [
                0x10, 0x30, 0xab, 0xed, 0x06, 0x5a, 0x2f, 0xaf, 0xe7, 0x1c, 0x6b, 0x83, 0x6d, 0xbb,
                0x28, 0x35, 0x6e, 0x0c, 0x62, 0x54
            ]
        );
    }

    #[test]
    fn recognises_prefix_case_insensitively() {
        assert!(is_legacy_name("ft_1.dat"));
        assert!(is_legacy_name("FT_99.dat"));
        assert!(!is_legacy_name("armorgrp.dat"));
        assert!(!is_legacy_name("ft"));
    }

    fn build_manifest() -> Vec<u8> {
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
        let manifest = parse(&build_manifest()).unwrap();
        assert_eq!(manifest.records.len(), 1);
        assert_eq!(manifest.records[0].path, "system/l2.exe");
        assert_eq!(manifest.records[0].digests[0], vec![0xAB, 0xCD]);
    }

    #[test]
    fn round_trips_through_rc4() {
        let encrypted = rc4::crypt(&build_manifest(), &legacy_key());
        let text = decode(&encrypted).unwrap();
        assert!(text.contains("system/l2.exe"));
    }

    #[test]
    fn rejects_garbage_instead_of_allocating() {
        let garbage = vec![0xFFu8; 64];
        assert!(parse(&garbage).is_err());
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut data = build_manifest();
        data.push(0);
        assert!(parse(&data).is_err());
    }
}
