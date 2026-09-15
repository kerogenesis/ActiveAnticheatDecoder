//! Tiny dependency-free helpers shared by `decoder` and `aa_proxy`.

#[must_use]
pub fn read_u16(bytes: &[u8], at: usize) -> Option<u16> {
    bytes.get(at..at + 2).map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
}

#[must_use]
pub fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    bytes.get(at..at + 4).map(|quad| u32::from_le_bytes([quad[0], quad[1], quad[2], quad[3]]))
}

#[must_use]
pub fn wide_nul(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(core::iter::once(0)).collect()
}

#[must_use]
pub fn to_wide(text: &str) -> Vec<u16> {
    wide_nul(text)
}

#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0F) as usize] as char);
    }
    out
}

#[must_use]
pub fn hex_to_bytes(text: &str) -> Option<Vec<u8>> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn le_readers_match_manual_decoding() {
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05];
        assert_eq!(read_u16(&bytes, 0), Some(0x0201));
        assert_eq!(read_u16(&bytes, 3), Some(0x0504));
        assert_eq!(read_u16(&bytes, 4), None);
        assert_eq!(read_u32(&bytes, 0), Some(0x0403_0201));
        assert_eq!(read_u32(&bytes, 2), None);
    }

    #[test]
    fn wide_strings_are_nul_terminated() {
        assert_eq!(wide_nul("A"), vec![0x41, 0x00]);
        assert_eq!(to_wide("A"), wide_nul("A"));
    }

    #[test]
    fn hex_roundtrips() {
        assert_eq!(hex_to_bytes("0100ff"), Some(vec![0x01, 0x00, 0xFF]));
        assert_eq!(hex_to_bytes(""), None);
        assert_eq!(hex_to_bytes("abc"), None);
        assert_eq!(hex_to_bytes("zz"), None);
        assert_eq!(to_hex(&[0xAB, 0xCD]), "abcd");
        let value = vec![0x01, 0x23, 0x45];
        assert_eq!(hex_to_bytes(&to_hex(&value)), Some(value));
    }
}
