//! Little-endian readers and NUL-terminated wide strings, shared by proxy and payload.

pub(super) fn read_u16(bytes: &[u8], at: usize) -> Option<u16> {
    bytes.get(at..at + 2).map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
}

pub(super) fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    bytes.get(at..at + 4).map(|quad| u32::from_le_bytes([quad[0], quad[1], quad[2], quad[3]]))
}

pub(super) fn wide_nul(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(core::iter::once(0)).collect()
}
