use crate::HASH_LEN_V1;

use super::TokenTransactionErrorV1;

pub(crate) fn encode_hex_lower_v1(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

pub(crate) fn decode_hex_32_v1(
    field: &'static str,
    input: &str,
) -> Result<[u8; HASH_LEN_V1], TokenTransactionErrorV1> {
    if input.len() != HASH_LEN_V1 * 2 {
        return Err(TokenTransactionErrorV1::InvalidHexLength {
            field,
            expected_bytes: HASH_LEN_V1,
            actual_nibbles: input.len(),
        });
    }

    let mut bytes = [0u8; HASH_LEN_V1];
    let input_bytes = input.as_bytes();
    for (index, chunk) in input_bytes.chunks_exact(2).enumerate() {
        let high = decode_hex_nibble_v1(chunk[0])
            .ok_or(TokenTransactionErrorV1::MalformedHex { field })?;
        let low = decode_hex_nibble_v1(chunk[1])
            .ok_or(TokenTransactionErrorV1::MalformedHex { field })?;
        bytes[index] = (high << 4) | low;
    }
    Ok(bytes)
}

fn decode_hex_nibble_v1(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}
