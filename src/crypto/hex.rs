pub use aa_shared::{hex_to_bytes, to_hex};

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
