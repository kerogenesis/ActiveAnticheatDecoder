//! Fixed-width 2048-bit modular arithmetic (u32 limbs, Montgomery CIOS).

pub const LIMBS: usize = 64; // 64 * 32 = 2048 bits

pub type Big = [u32; LIMBS];

pub fn from_be_bytes(bytes: &[u8]) -> Option<Big> {
    if bytes.len() > LIMBS * 4 {
        return None;
    }
    let mut out = [0u32; LIMBS];
    for (index, byte) in bytes.iter().rev().enumerate() {
        out[index / 4] |= (*byte as u32) << (8 * (index % 4));
    }
    Some(out)
}

pub fn from_le_bytes(bytes: &[u8]) -> Option<Big> {
    if bytes.len() > LIMBS * 4 {
        return None;
    }
    let mut out = [0u32; LIMBS];
    for (index, byte) in bytes.iter().enumerate() {
        out[index / 4] |= (*byte as u32) << (8 * (index % 4));
    }
    Some(out)
}

pub fn to_be_bytes(value: &Big) -> [u8; LIMBS * 4] {
    let mut out = [0u8; LIMBS * 4];
    for index in 0..LIMBS * 4 {
        out[LIMBS * 4 - 1 - index] = (value[index / 4] >> (8 * (index % 4))) as u8;
    }
    out
}

pub fn is_zero(value: &Big) -> bool {
    value.iter().all(|limb| *limb == 0)
}

pub fn greater_or_equal(a: &Big, b: &Big) -> bool {
    for index in (0..LIMBS).rev() {
        if a[index] != b[index] {
            return a[index] > b[index];
        }
    }
    true
}

fn sub_assign(a: &mut Big, b: &Big) {
    let mut borrow = 0u64;
    for index in 0..LIMBS {
        let diff = (a[index] as u64)
            .wrapping_sub(b[index] as u64)
            .wrapping_sub(borrow);
        a[index] = diff as u32;
        borrow = (diff >> 63) & 1;
    }
}

fn double_mod(a: &mut Big, n: &Big) {
    let mut carry = 0u64;
    for limb in a.iter_mut() {
        let shifted = ((*limb as u64) << 1) | carry;
        *limb = shifted as u32;
        carry = shifted >> 32;
    }
    if carry != 0 || greater_or_equal(a, n) {
        sub_assign(a, n);
    }
}

fn inverse_n0(n0: u32) -> u32 {
    let mut inv: u32 = 1;
    for _ in 0..5 {
        inv = inv.wrapping_mul(2u32.wrapping_sub(n0.wrapping_mul(inv)));
    }
    inv.wrapping_neg()
}

fn mont_mul(a: &Big, b: &Big, n: &Big, n_prime0: u32) -> Big {
    let mut t = [0u64; LIMBS + 2];
    for &b_limb in b {
        let mut carry = 0u64;
        let bi = b_limb as u64;
        for j in 0..LIMBS {
            let sum = t[j] + (a[j] as u64) * bi + carry;
            t[j] = sum & 0xFFFF_FFFF;
            carry = sum >> 32;
        }
        let sum = t[LIMBS] + carry;
        t[LIMBS] = sum & 0xFFFF_FFFF;
        t[LIMBS + 1] += sum >> 32;

        let m = ((t[0] as u32).wrapping_mul(n_prime0)) as u64;
        let mut carry = 0u64;
        for j in 0..LIMBS {
            let sum = t[j] + m * (n[j] as u64) + carry;
            t[j] = sum & 0xFFFF_FFFF;
            carry = sum >> 32;
        }
        let sum = t[LIMBS] + carry;
        t[LIMBS] = sum & 0xFFFF_FFFF;
        t[LIMBS + 1] += sum >> 32;

        for j in 0..=LIMBS {
            t[j] = t[j + 1];
        }
        t[LIMBS + 1] = 0;
    }

    let mut result = [0u32; LIMBS];
    for index in 0..LIMBS {
        result[index] = t[index] as u32;
    }
    if t[LIMBS] != 0 || greater_or_equal(&result, n) {
        sub_assign(&mut result, n);
    }
    result
}

fn compute_r2(n: &Big) -> Big {
    let mut x = [0u32; LIMBS];
    x[0] = 1;
    for _ in 0..(2 * 32 * LIMBS) {
        double_mod(&mut x, n);
    }
    x
}

pub fn mod_pow(base: &Big, exponent_be: &[u8], n: &Big) -> Big {
    let n_prime0 = inverse_n0(n[0]);
    let r2 = compute_r2(n);
    let mut one = [0u32; LIMBS];
    one[0] = 1;

    let base_mont = mont_mul(base, &r2, n, n_prime0);
    let mut result = mont_mul(&one, &r2, n, n_prime0);

    let mut started = false;
    for byte in exponent_be {
        for bit in (0..8).rev() {
            let is_set = (byte >> bit) & 1 == 1;
            if !started {
                if !is_set {
                    continue;
                }
                started = true;
                result = base_mont;
                continue;
            }
            result = mont_mul(&result, &result, n, n_prime0);
            if is_set {
                result = mont_mul(&result, &base_mont, n, n_prime0);
            }
        }
    }
    if !started {
        return one;
    }
    mont_mul(&result, &one, n, n_prime0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mod_pow_small_values() {
        let base = from_be_bytes(&[5]).unwrap();
        let modulus = from_be_bytes(&[13]).unwrap();
        let result = mod_pow(&base, &[3], &modulus);
        assert_eq!(result[0], 8);
    }

    #[test]
    fn mod_pow_exponent_zero_is_one() {
        let base = from_be_bytes(&[7]).unwrap();
        let modulus = from_be_bytes(&[13]).unwrap();
        let result = mod_pow(&base, &[0], &modulus);
        assert_eq!(result[0], 1);
    }

    #[test]
    fn mod_pow_satisfies_fermats_little_theorem() {
        let mut p_bytes = [0xFFu8; 16];
        p_bytes[0] = 0x7F;
        let mut exponent = p_bytes;
        exponent[15] = 0xFE;

        let modulus = from_be_bytes(&p_bytes).unwrap();
        let base = from_be_bytes(&[3]).unwrap();
        let result = mod_pow(&base, &exponent, &modulus);

        let mut expected = [0u32; LIMBS];
        expected[0] = 1;
        assert_eq!(result, expected);
    }

    #[test]
    fn byte_roundtrip_is_stable() {
        let mut bytes = [0u8; 256];
        for (index, slot) in bytes.iter_mut().enumerate() {
            *slot = (index * 7 + 1) as u8;
        }
        let value = from_be_bytes(&bytes).unwrap();
        assert_eq!(to_be_bytes(&value), bytes);
    }
}
