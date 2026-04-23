//! Canonical pair-state representation for the storm lower layer.

use core::fmt;

use crate::{
    FieldElement521V1, FieldElementErrorV1, FIELD_ELEMENT_521_BYTE_LEN_V1,
};

pub const STORM_STATE_521_ROW_BYTE_LEN_V1: usize = FIELD_ELEMENT_521_BYTE_LEN_V1 * 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StormState521V1 {
    pub x: FieldElement521V1,
    pub y: FieldElement521V1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StormStateEncodingErrorV1 {
    InvalidLength { expected: usize, actual: usize },
    InvalidX(FieldElementErrorV1),
    InvalidY(FieldElementErrorV1),
}

impl fmt::Display for StormStateEncodingErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(
                    f,
                    "invalid storm row length: expected {expected} bytes, got {actual}"
                )
            }
            Self::InvalidX(error) => write!(f, "invalid storm x coordinate: {error}"),
            Self::InvalidY(error) => write!(f, "invalid storm y coordinate: {error}"),
        }
    }
}

impl std::error::Error for StormStateEncodingErrorV1 {}

impl StormState521V1 {
    pub fn encode_row_bytes(&self) -> [u8; STORM_STATE_521_ROW_BYTE_LEN_V1] {
        let mut bytes = [0u8; STORM_STATE_521_ROW_BYTE_LEN_V1];
        bytes[..FIELD_ELEMENT_521_BYTE_LEN_V1].copy_from_slice(&self.x.to_bytes());
        bytes[FIELD_ELEMENT_521_BYTE_LEN_V1..].copy_from_slice(&self.y.to_bytes());
        bytes
    }
}

pub fn decode_row_bytes(bytes: &[u8]) -> Result<StormState521V1, StormStateEncodingErrorV1> {
    if bytes.len() != STORM_STATE_521_ROW_BYTE_LEN_V1 {
        return Err(StormStateEncodingErrorV1::InvalidLength {
            expected: STORM_STATE_521_ROW_BYTE_LEN_V1,
            actual: bytes.len(),
        });
    }

    let mut x_bytes = [0u8; FIELD_ELEMENT_521_BYTE_LEN_V1];
    x_bytes.copy_from_slice(&bytes[..FIELD_ELEMENT_521_BYTE_LEN_V1]);

    let mut y_bytes = [0u8; FIELD_ELEMENT_521_BYTE_LEN_V1];
    y_bytes.copy_from_slice(&bytes[FIELD_ELEMENT_521_BYTE_LEN_V1..]);

    Ok(StormState521V1 {
        x: FieldElement521V1::from_bytes(x_bytes)
            .map_err(StormStateEncodingErrorV1::InvalidX)?,
        y: FieldElement521V1::from_bytes(y_bytes)
            .map_err(StormStateEncodingErrorV1::InvalidY)?,
    })
}

#[cfg(test)]
mod tests {
    use crate::FieldElement521V1;

    use super::{decode_row_bytes, StormState521V1, STORM_STATE_521_ROW_BYTE_LEN_V1};

    #[test]
    fn storm_row_round_trips() {
        let state = StormState521V1 {
            x: FieldElement521V1::from_u64(17),
            y: FieldElement521V1::from_u64(23),
        };

        let encoded = state.encode_row_bytes();

        assert_eq!(encoded.len(), STORM_STATE_521_ROW_BYTE_LEN_V1);
        assert_eq!(decode_row_bytes(&encoded).unwrap(), state);
    }
}
