// Upgraded from dissipative quadratic map to Arnold cat map (Fibonacci-log structure)
// Matrix: [[1,1],[1,2]] mod (2^521-1)
// Date: 2026-03-26
//! Minimal deterministic 521-bit field element representation and cat-map-oriented arithmetic.
//!
//! This module defines only:
//! - canonical fixed-width representation
//! - fail-closed parsing
//! - deterministic serialization
//! - arbitrary-byte reduction into the field
//! - modular addition, subtraction, multiplication, and squaring under `2^521 - 1`
//!
//! It intentionally does not define a broader arithmetic framework.

use core::fmt;

pub const FIELD_ELEMENT_521_BYTE_LEN_V1: usize = 66;
const FIELD_ELEMENT_521_LIMB_COUNT_V1: usize = 17;
const FIELD_ELEMENT_521_PRODUCT_LIMB_COUNT_V1: usize = FIELD_ELEMENT_521_LIMB_COUNT_V1 * 2;
const FIELD_ELEMENT_521_TOP_LIMB_MASK_V1: u32 = 0x01ff;

/// Canonical big-endian encoding of `2^521 - 1`.
pub const FIELD_MODULUS_521_V1: [u8; FIELD_ELEMENT_521_BYTE_LEN_V1] = [
    0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff,
];

const FIELD_MODULUS_521_LIMBS_V1: [u32; FIELD_ELEMENT_521_LIMB_COUNT_V1] = [
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    FIELD_ELEMENT_521_TOP_LIMB_MASK_V1,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldElement521V1 {
    bytes: [u8; FIELD_ELEMENT_521_BYTE_LEN_V1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldElementErrorV1 {
    InvalidTopBits,
    ValueOutOfRange,
    NonCanonicalEncoding,
}

impl fmt::Display for FieldElementErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTopBits => {
                write!(f, "invalid top bits: top 7 bits of byte 0 must be zero")
            }
            Self::ValueOutOfRange => write!(f, "field element value out of range"),
            Self::NonCanonicalEncoding => write!(f, "non-canonical field element encoding"),
        }
    }
}

impl std::error::Error for FieldElementErrorV1 {}

impl FieldElement521V1 {
    pub const fn zero() -> Self {
        Self {
            bytes: [0u8; FIELD_ELEMENT_521_BYTE_LEN_V1],
        }
    }

    pub fn one() -> Self {
        Self::from_u64(1)
    }

    pub fn from_u64(value: u64) -> Self {
        let mut bytes = [0u8; FIELD_ELEMENT_521_BYTE_LEN_V1];
        bytes[FIELD_ELEMENT_521_BYTE_LEN_V1 - 8..].copy_from_slice(&value.to_be_bytes());
        Self { bytes }
    }

    pub fn reduce_bytes_mod(bytes: &[u8]) -> Self {
        let radix = Self::from_u64(256);
        let mut reduced = Self::zero();

        for byte in bytes {
            reduced = reduced
                .mul_mod(&radix)
                .add_mod(&Self::from_u64(u64::from(*byte)));
        }

        reduced
    }

    pub fn from_bytes(
        input: [u8; FIELD_ELEMENT_521_BYTE_LEN_V1],
    ) -> Result<Self, FieldElementErrorV1> {
        if input[0] & 0xfe != 0 {
            return Err(FieldElementErrorV1::InvalidTopBits);
        }

        let limbs = bytes_to_limbs_le(&input);
        let canonical = limbs_to_bytes_be(&limbs);
        if input != canonical {
            return Err(FieldElementErrorV1::NonCanonicalEncoding);
        }

        if compare_limbs_le(&limbs, &FIELD_MODULUS_521_LIMBS_V1).is_ge() {
            return Err(FieldElementErrorV1::ValueOutOfRange);
        }

        Ok(Self { bytes: input })
    }

    pub fn to_bytes(&self) -> [u8; FIELD_ELEMENT_521_BYTE_LEN_V1] {
        self.bytes
    }

    pub fn is_zero(&self) -> bool {
        self.bytes == [0u8; FIELD_ELEMENT_521_BYTE_LEN_V1]
    }

    pub fn add_mod(&self, rhs: &Self) -> Self {
        let lhs_limbs = bytes_to_limbs_le(&self.bytes);
        let rhs_limbs = bytes_to_limbs_le(&rhs.bytes);
        let reduced = add_modulus_521(lhs_limbs, rhs_limbs);

        Self {
            bytes: limbs_to_bytes_be(&reduced),
        }
    }

    pub fn sub_mod(&self, rhs: &Self) -> Self {
        let lhs_limbs = bytes_to_limbs_le(&self.bytes);
        let rhs_limbs = bytes_to_limbs_le(&rhs.bytes);
        let reduced = match compare_limbs_le(&lhs_limbs, &rhs_limbs) {
            OrderingV1::Greater | OrderingV1::Equal => subtract_limbs_once(lhs_limbs, rhs_limbs),
            OrderingV1::Less => {
                let delta = subtract_limbs_once(rhs_limbs, lhs_limbs);
                subtract_limbs_once(FIELD_MODULUS_521_LIMBS_V1, delta)
            }
        };

        Self {
            bytes: limbs_to_bytes_be(&reduced),
        }
    }

    pub fn mul_mod(&self, rhs: &Self) -> Self {
        let lhs_limbs = bytes_to_limbs_le(&self.bytes);
        let rhs_limbs = bytes_to_limbs_le(&rhs.bytes);
        let product = multiply_limbs_521(lhs_limbs, rhs_limbs);
        let reduced = reduce_product_modulus_521(product);

        Self {
            bytes: limbs_to_bytes_be(&reduced),
        }
    }

    pub fn square_mod(&self) -> Self {
        self.mul_mod(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OrderingV1 {
    Less,
    Equal,
    Greater,
}

impl OrderingV1 {
    const fn is_ge(self) -> bool {
        matches!(self, Self::Equal | Self::Greater)
    }
}

fn bytes_to_limbs_le(
    bytes: &[u8; FIELD_ELEMENT_521_BYTE_LEN_V1],
) -> [u32; FIELD_ELEMENT_521_LIMB_COUNT_V1] {
    let mut limbs = [0u32; FIELD_ELEMENT_521_LIMB_COUNT_V1];
    let mut limb_index = 0usize;
    let mut remaining = FIELD_ELEMENT_521_BYTE_LEN_V1;

    while remaining > 0 {
        let take = remaining.min(4);
        let start = remaining - take;
        let mut chunk = [0u8; 4];
        chunk[4 - take..].copy_from_slice(&bytes[start..remaining]);
        limbs[limb_index] = u32::from_be_bytes(chunk);
        limb_index += 1;
        remaining = start;
    }

    limbs
}

fn limbs_to_bytes_be(
    limbs: &[u32; FIELD_ELEMENT_521_LIMB_COUNT_V1],
) -> [u8; FIELD_ELEMENT_521_BYTE_LEN_V1] {
    let mut bytes = [0u8; FIELD_ELEMENT_521_BYTE_LEN_V1];

    for (limb_index, limb) in limbs.iter().take(16).enumerate() {
        let end = FIELD_ELEMENT_521_BYTE_LEN_V1 - limb_index * 4;
        let start = end - 4;
        bytes[start..end].copy_from_slice(&limb.to_be_bytes());
    }

    let top_bytes = limbs[16].to_be_bytes();
    bytes[0..2].copy_from_slice(&top_bytes[2..4]);
    debug_assert_eq!(bytes[0] & 0xfe, 0);

    bytes
}

fn compare_limbs_le(
    lhs: &[u32; FIELD_ELEMENT_521_LIMB_COUNT_V1],
    rhs: &[u32; FIELD_ELEMENT_521_LIMB_COUNT_V1],
) -> OrderingV1 {
    for index in (0..FIELD_ELEMENT_521_LIMB_COUNT_V1).rev() {
        if lhs[index] < rhs[index] {
            return OrderingV1::Less;
        }
        if lhs[index] > rhs[index] {
            return OrderingV1::Greater;
        }
    }

    OrderingV1::Equal
}

fn add_modulus_521(
    lhs: [u32; FIELD_ELEMENT_521_LIMB_COUNT_V1],
    rhs: [u32; FIELD_ELEMENT_521_LIMB_COUNT_V1],
) -> [u32; FIELD_ELEMENT_521_LIMB_COUNT_V1] {
    let mut sum = [0u32; FIELD_ELEMENT_521_LIMB_COUNT_V1];
    let mut carry = 0u64;

    for index in 0..FIELD_ELEMENT_521_LIMB_COUNT_V1 {
        let total = lhs[index] as u64 + rhs[index] as u64 + carry;
        sum[index] = total as u32;
        carry = total >> 32;
    }

    debug_assert_eq!(carry, 0);
    reduce_folded_521(sum)
}

fn subtract_limbs_once(
    lhs: [u32; FIELD_ELEMENT_521_LIMB_COUNT_V1],
    rhs: [u32; FIELD_ELEMENT_521_LIMB_COUNT_V1],
) -> [u32; FIELD_ELEMENT_521_LIMB_COUNT_V1] {
    let mut output = [0u32; FIELD_ELEMENT_521_LIMB_COUNT_V1];
    let mut borrow = 0u64;

    for index in 0..FIELD_ELEMENT_521_LIMB_COUNT_V1 {
        let rhs = rhs[index] as u64 + borrow;
        let lhs = lhs[index] as u64;

        if lhs >= rhs {
            output[index] = (lhs - rhs) as u32;
            borrow = 0;
        } else {
            output[index] = ((1u64 << 32) + lhs - rhs) as u32;
            borrow = 1;
        }
    }

    debug_assert_eq!(borrow, 0);
    output
}

fn multiply_limbs_521(
    lhs: [u32; FIELD_ELEMENT_521_LIMB_COUNT_V1],
    rhs: [u32; FIELD_ELEMENT_521_LIMB_COUNT_V1],
) -> [u32; FIELD_ELEMENT_521_PRODUCT_LIMB_COUNT_V1] {
    let mut accum = [0u128; FIELD_ELEMENT_521_PRODUCT_LIMB_COUNT_V1];

    for lhs_index in 0..FIELD_ELEMENT_521_LIMB_COUNT_V1 {
        for rhs_index in 0..FIELD_ELEMENT_521_LIMB_COUNT_V1 {
            accum[lhs_index + rhs_index] += (lhs[lhs_index] as u128) * (rhs[rhs_index] as u128);
        }
    }

    let mut product = [0u32; FIELD_ELEMENT_521_PRODUCT_LIMB_COUNT_V1];
    let mut carry = 0u128;
    for index in 0..FIELD_ELEMENT_521_PRODUCT_LIMB_COUNT_V1 {
        let total = accum[index] + carry;
        product[index] = (total & 0xffff_ffff) as u32;
        carry = total >> 32;
    }

    debug_assert_eq!(carry, 0);
    product
}

fn reduce_product_modulus_521(
    product: [u32; FIELD_ELEMENT_521_PRODUCT_LIMB_COUNT_V1],
) -> [u32; FIELD_ELEMENT_521_LIMB_COUNT_V1] {
    let mut low = [0u32; FIELD_ELEMENT_521_LIMB_COUNT_V1];
    low[..16].copy_from_slice(&product[..16]);
    low[16] = product[16] & FIELD_ELEMENT_521_TOP_LIMB_MASK_V1;

    let mut high = [0u32; FIELD_ELEMENT_521_LIMB_COUNT_V1];
    for index in 0..FIELD_ELEMENT_521_LIMB_COUNT_V1 {
        let lower_source = index + 16;
        let upper_source = index + 17;

        let lower = if lower_source < FIELD_ELEMENT_521_PRODUCT_LIMB_COUNT_V1 {
            (product[lower_source] as u64) >> 9
        } else {
            0
        };
        let upper = if upper_source < FIELD_ELEMENT_521_PRODUCT_LIMB_COUNT_V1 {
            (product[upper_source] as u64) << 23
        } else {
            0
        };

        high[index] = (lower | upper) as u32;
    }

    debug_assert_eq!(high[16] & !FIELD_ELEMENT_521_TOP_LIMB_MASK_V1, 0);

    add_modulus_521(low, high)
}

fn reduce_folded_521(
    mut value: [u32; FIELD_ELEMENT_521_LIMB_COUNT_V1],
) -> [u32; FIELD_ELEMENT_521_LIMB_COUNT_V1] {
    loop {
        let carry = value[16] >> 9;
        value[16] &= FIELD_ELEMENT_521_TOP_LIMB_MASK_V1;
        if carry == 0 {
            break;
        }

        let mut carry_add = carry as u64;
        for limb in &mut value {
            if carry_add == 0 {
                break;
            }

            let total = *limb as u64 + carry_add;
            *limb = total as u32;
            carry_add = total >> 32;
        }

        debug_assert_eq!(carry_add, 0);
    }

    while compare_limbs_le(&value, &FIELD_MODULUS_521_LIMBS_V1).is_ge() {
        value = subtract_limbs_once(value, FIELD_MODULUS_521_LIMBS_V1);
    }

    value
}

#[cfg(test)]
mod tests {
    use super::{
        FieldElement521V1, FieldElementErrorV1, FIELD_ELEMENT_521_BYTE_LEN_V1, FIELD_MODULUS_521_V1,
    };

    #[test]
    fn canonical_zero_is_valid() {
        let bytes = [0u8; FIELD_ELEMENT_521_BYTE_LEN_V1];
        let element = FieldElement521V1::from_bytes(bytes).unwrap();

        assert_eq!(element.to_bytes(), bytes);
    }

    #[test]
    fn canonical_one_is_valid() {
        let bytes = small_value_bytes(1);
        let element = FieldElement521V1::from_bytes(bytes).unwrap();

        assert_eq!(element.to_bytes(), bytes);
    }

    #[test]
    fn canonical_max_minus_one_is_valid() {
        let mut bytes = FIELD_MODULUS_521_V1;
        bytes[FIELD_ELEMENT_521_BYTE_LEN_V1 - 1] = 0xfe;

        let element = FieldElement521V1::from_bytes(bytes).unwrap();
        assert_eq!(element.to_bytes(), bytes);
    }

    #[test]
    fn highest_legal_top_bit_value_is_valid() {
        let bytes = top_bit_value_bytes(0);
        let element = FieldElement521V1::from_bytes(bytes).unwrap();

        assert_eq!(element.to_bytes(), bytes);
    }

    #[test]
    fn modulus_rejects() {
        let error = FieldElement521V1::from_bytes(FIELD_MODULUS_521_V1).unwrap_err();

        assert_eq!(error, FieldElementErrorV1::ValueOutOfRange);
    }

    #[test]
    fn top_bits_set_rejects() {
        let mut bytes = [0u8; FIELD_ELEMENT_521_BYTE_LEN_V1];
        bytes[0] = 0x80;

        let error = FieldElement521V1::from_bytes(bytes).unwrap_err();
        assert_eq!(error, FieldElementErrorV1::InvalidTopBits);
    }

    #[test]
    fn top_bit_edge_condition_rejects_first_forbidden_bit() {
        let mut bytes = [0u8; FIELD_ELEMENT_521_BYTE_LEN_V1];
        bytes[0] = 0x02;

        let error = FieldElement521V1::from_bytes(bytes).unwrap_err();
        assert_eq!(error, FieldElementErrorV1::InvalidTopBits);
    }

    #[test]
    fn roundtrip_identity() {
        let bytes = hex66(concat!(
            "01",
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "0a"
        ));
        let element = FieldElement521V1::from_bytes(bytes).unwrap();

        assert_eq!(element.to_bytes(), bytes);
    }

    #[test]
    fn reduction_from_empty_bytes_is_zero() {
        assert_eq!(
            FieldElement521V1::reduce_bytes_mod(&[]).to_bytes(),
            zero().to_bytes()
        );
    }

    #[test]
    fn reduction_from_single_byte_matches_small_value() {
        assert_eq!(
            FieldElement521V1::reduce_bytes_mod(&[0xab]).to_bytes(),
            small_value_bytes(0xab)
        );
    }

    #[test]
    fn reduction_of_modulus_followed_by_one_wraps_to_one() {
        let mut bytes = Vec::from(FIELD_MODULUS_521_V1);
        bytes.push(1);

        assert_eq!(
            FieldElement521V1::reduce_bytes_mod(&bytes).to_bytes(),
            one().to_bytes()
        );
    }

    #[test]
    fn important_edge_values_roundtrip_canonically() {
        let edge_values = [
            [0u8; FIELD_ELEMENT_521_BYTE_LEN_V1],
            small_value_bytes(1),
            modulus_minus_small_bytes(1),
            top_bit_value_bytes(0),
            top_bit_value_bytes(10),
        ];

        for bytes in edge_values {
            let element = FieldElement521V1::from_bytes(bytes).unwrap();
            assert_eq!(element.to_bytes(), bytes);
        }
    }

    #[test]
    fn modified_byte_changes_value() {
        let first_bytes = hex66(concat!(
            "00",
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "01"
        ));
        let second_bytes = hex66(concat!(
            "00",
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "02"
        ));

        let first = FieldElement521V1::from_bytes(first_bytes).unwrap();
        let second = FieldElement521V1::from_bytes(second_bytes).unwrap();

        assert_ne!(first.to_bytes(), second.to_bytes());
    }

    #[test]
    fn addition_zero_plus_zero_is_zero() {
        let sum = zero().add_mod(&zero());

        assert_eq!(sum.to_bytes(), zero().to_bytes());
    }

    #[test]
    fn addition_zero_plus_one_is_one() {
        let sum = zero().add_mod(&one());

        assert_eq!(sum.to_bytes(), one().to_bytes());
    }

    #[test]
    fn addition_max_minus_one_plus_one_wraps_to_zero() {
        let sum = max_minus_one().add_mod(&one());

        assert_eq!(sum.to_bytes(), zero().to_bytes());
    }

    #[test]
    fn subtraction_zero_minus_one_wraps_to_max_minus_one() {
        let difference = zero().sub_mod(&one());

        assert_eq!(difference.to_bytes(), max_minus_one().to_bytes());
    }

    #[test]
    fn subtraction_one_minus_max_minus_one_yields_two() {
        let difference = one().sub_mod(&max_minus_one());

        assert_eq!(difference.to_bytes(), small_value_bytes(2));
    }

    #[test]
    fn multiplication_zero_is_zero() {
        let product = zero().mul_mod(&top_bit_value(10));

        assert_eq!(product.to_bytes(), zero().to_bytes());
    }

    #[test]
    fn multiplication_one_is_identity() {
        let product = one().mul_mod(&top_bit_value(10));

        assert_eq!(product.to_bytes(), top_bit_value(10).to_bytes());
    }

    #[test]
    fn multiplication_small_known_value_matches_expected_result() {
        let product = small_value(5).mul_mod(&small_value(7));

        assert_eq!(product.to_bytes(), small_value_bytes(35));
    }

    #[test]
    fn multiplication_max_minus_one_times_max_minus_one_is_one() {
        let product = max_minus_one().mul_mod(&max_minus_one());

        assert_eq!(product.to_bytes(), one().to_bytes());
    }

    #[test]
    fn squaring_zero_is_zero() {
        let square = zero().square_mod();

        assert_eq!(square.to_bytes(), zero().to_bytes());
    }

    #[test]
    fn squaring_one_is_one() {
        let square = one().square_mod();

        assert_eq!(square.to_bytes(), one().to_bytes());
    }

    #[test]
    fn squaring_max_minus_one_is_one() {
        let square = max_minus_one().square_mod();

        assert_eq!(square.to_bytes(), one().to_bytes());
    }

    #[test]
    fn squaring_small_known_value_matches_expected_result() {
        let square = small_value(5).square_mod();

        assert_eq!(square.to_bytes(), small_value_bytes(25));
    }

    #[test]
    fn squaring_boundary_adjacent_value_matches_expected_result() {
        let square = max_minus_two().square_mod();

        assert_eq!(square.to_bytes(), small_value_bytes(4));
    }

    #[test]
    fn pinned_vector_is_valid() {
        let bytes = hex66(concat!(
            "01",
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "aa"
        ));

        let element = FieldElement521V1::from_bytes(bytes).unwrap();
        assert_eq!(element.to_bytes(), bytes);
    }

    fn zero() -> FieldElement521V1 {
        FieldElement521V1::zero()
    }

    fn one() -> FieldElement521V1 {
        small_value(1)
    }

    fn max_minus_one() -> FieldElement521V1 {
        FieldElement521V1::from_bytes(modulus_minus_small_bytes(1)).unwrap()
    }

    fn max_minus_two() -> FieldElement521V1 {
        FieldElement521V1::from_bytes(modulus_minus_small_bytes(2)).unwrap()
    }

    fn small_value(value: u8) -> FieldElement521V1 {
        FieldElement521V1::from_bytes(small_value_bytes(value)).unwrap()
    }

    fn small_value_bytes(value: u8) -> [u8; FIELD_ELEMENT_521_BYTE_LEN_V1] {
        let mut bytes = [0u8; FIELD_ELEMENT_521_BYTE_LEN_V1];
        bytes[FIELD_ELEMENT_521_BYTE_LEN_V1 - 1] = value;
        bytes
    }

    fn modulus_minus_small_bytes(value: u8) -> [u8; FIELD_ELEMENT_521_BYTE_LEN_V1] {
        assert!(value > 0);

        let mut bytes = FIELD_MODULUS_521_V1;
        bytes[FIELD_ELEMENT_521_BYTE_LEN_V1 - 1] = 0xff - value;
        bytes
    }

    fn top_bit_value(low_byte: u8) -> FieldElement521V1 {
        FieldElement521V1::from_bytes(top_bit_value_bytes(low_byte)).unwrap()
    }

    fn top_bit_value_bytes(low_byte: u8) -> [u8; FIELD_ELEMENT_521_BYTE_LEN_V1] {
        let mut bytes = [0u8; FIELD_ELEMENT_521_BYTE_LEN_V1];
        bytes[0] = 0x01;
        bytes[FIELD_ELEMENT_521_BYTE_LEN_V1 - 1] = low_byte;
        bytes
    }

    fn hex66(input: &str) -> [u8; FIELD_ELEMENT_521_BYTE_LEN_V1] {
        let bytes = input.as_bytes();
        assert_eq!(bytes.len(), FIELD_ELEMENT_521_BYTE_LEN_V1 * 2);

        let mut output = [0u8; FIELD_ELEMENT_521_BYTE_LEN_V1];
        let mut index = 0usize;
        while index < FIELD_ELEMENT_521_BYTE_LEN_V1 {
            let hi = decode_hex_nibble(bytes[index * 2]);
            let lo = decode_hex_nibble(bytes[index * 2 + 1]);
            output[index] = (hi << 4) | lo;
            index += 1;
        }
        output
    }

    fn decode_hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("invalid hex byte in test vector"),
        }
    }
}
