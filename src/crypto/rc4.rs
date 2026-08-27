//! Plain RC4. Shared by the Hash manifest `ft_*` path and the AAC payload path.

pub fn crypt_in_place(data: &mut [u8], key: &[u8]) {
    assert!(!key.is_empty(), "RC4 key must not be empty");
    let mut state = [0u8; 256];
    for (index, byte) in state.iter_mut().enumerate() {
        *byte = index as u8;
    }
    let mut j = 0u8;
    for i in 0..256 {
        j = j.wrapping_add(state[i]).wrapping_add(key[i % key.len()]);
        state.swap(i, j as usize);
    }
    let mut i = 0u8;
    let mut j = 0u8;
    for byte in data {
        i = i.wrapping_add(1);
        j = j.wrapping_add(state[i as usize]);
        state.swap(i as usize, j as usize);
        let index = state[i as usize].wrapping_add(state[j as usize]);
        *byte ^= state[index as usize];
    }
}

pub fn crypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut output = data.to_vec();
    crypt_in_place(&mut output, key);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_known_rc4_vector() {
        let output = crypt(b"Plaintext", b"Key");
        assert_eq!(output, vec![0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]);
    }

    #[test]
    fn is_an_involution() {
        let key = b"some key";
        let data = b"round trip payload";
        let encrypted = crypt(data, key);
        assert_eq!(crypt(&encrypted, key), data.to_vec());
    }
}
