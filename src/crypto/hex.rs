use std::fmt::Write as _;

/// Decode even-length lowercase/uppercase hex to bytes.
/// Returns `None` on odd length or non-hex digit.
pub fn hex_to_bytes(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || text.len() % 2 != 0 {
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

pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        assert_eq!(hex_to_bytes("0100ff"), Some(vec![0x01, 0x00, 0xff]));
        assert_eq!(hex_to_bytes(""), None);
        assert_eq!(hex_to_bytes("abc"), None);
        assert_eq!(hex_to_bytes("zz"), None);
        assert_eq!(to_hex(&[0xab, 0xcd]), "abcd");
        let v = vec![0x01, 0x23, 0x45];
        assert_eq!(hex_to_bytes(&to_hex(&v)).unwrap(), v);
    }
}
