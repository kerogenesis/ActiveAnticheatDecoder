//! Scryde GamekitData header detection.

use std::fmt;

const GAMEKIT_HEADER: &[u8; 22] = b"G\0a\0m\0e\0k\0i\0t\0D\0a\0t\0a\0";
const LINEAGE2_HEADER: &[u8; 22] = b"L\0i\0n\0e\0a\0g\0e\x002\0V\0e\0r\0";

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
