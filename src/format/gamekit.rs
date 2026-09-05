//! Scryde GamekitData header detection.

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

/// Patch a GamekitData header into its Lineage2Ver shape in place.
/// Returns whether the buffer held a recognised header.
pub fn patch_to_lineage2(data: &mut [u8]) -> bool {
    if detect_format(data).is_none() {
        return false;
    }
    data[..GAMEKIT_HEADER.len()].copy_from_slice(LINEAGE2_HEADER);
    true
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

        assert!(patch_to_lineage2(&mut data));
        assert_eq!(&data[..22], LINEAGE2_HEADER);
        assert_eq!(&data[22..28], &[b'1', 0, b'1', 0, b'1', 0]);
    }

    #[test]
    fn leaves_unknown_data_untouched() {
        let mut data = vec![0u8; 40];
        assert!(!patch_to_lineage2(&mut data));
        assert_eq!(data, vec![0u8; 40]);
    }
}
