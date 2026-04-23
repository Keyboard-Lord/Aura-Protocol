use core::fmt;

pub const UDOT_HASH_LEN: usize = 32;
const UDOT_HASH_HEX_LEN: usize = UDOT_HASH_LEN * 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AuraHashBytes([u8; UDOT_HASH_LEN]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UdotHashError {
    InvalidLength { expected: usize, actual: usize },
    InvalidWhitespace { index: usize, value: char },
    InvalidCharacter { index: usize, value: char },
    NonCanonicalHex { expected: String, actual: String },
}

impl fmt::Display for UdotHashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(
                    f,
                    "invalid Aura hash text length: expected {expected}, got {actual}"
                )
            }
            Self::InvalidWhitespace { index, value } => {
                write!(
                    f,
                    "invalid Aura hash whitespace at index {index}: {value:?}"
                )
            }
            Self::InvalidCharacter { index, value } => {
                write!(f, "invalid Aura hash character at index {index}: {value:?}")
            }
            Self::NonCanonicalHex { expected, actual } => write!(
                f,
                "non-canonical Aura hash text: expected {expected}, got {actual}"
            ),
        }
    }
}

impl std::error::Error for UdotHashError {}

impl AuraHashBytes {
    pub const fn new(bytes: [u8; UDOT_HASH_LEN]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(input: &str) -> Result<Self, UdotHashError> {
        let char_count = input.chars().count();
        let mut bytes = [0u8; UDOT_HASH_LEN];

        for (index, value) in input.chars().enumerate() {
            if value.is_whitespace() {
                return Err(UdotHashError::InvalidWhitespace { index, value });
            }

            if decode_hex_nibble(value).is_none() {
                return Err(UdotHashError::InvalidCharacter { index, value });
            }
        }

        if char_count != UDOT_HASH_HEX_LEN {
            return Err(UdotHashError::InvalidLength {
                expected: UDOT_HASH_HEX_LEN,
                actual: char_count,
            });
        }

        for (index, chunk) in input
            .chars()
            .collect::<Vec<_>>()
            .chunks_exact(2)
            .enumerate()
        {
            let high = decode_hex_nibble(chunk[0]).expect("validated high nibble");
            let low = decode_hex_nibble(chunk[1]).expect("validated low nibble");
            bytes[index] = (high << 4) | low;
        }

        Ok(Self(bytes))
    }

    pub fn from_canonical_hex(input: &str) -> Result<Self, UdotHashError> {
        let parsed = Self::from_hex(input)?;
        let expected = parsed.to_lower_hex();

        if input != expected {
            return Err(UdotHashError::NonCanonicalHex {
                expected,
                actual: input.to_owned(),
            });
        }

        Ok(parsed)
    }

    pub fn as_bytes(&self) -> &[u8; UDOT_HASH_LEN] {
        &self.0
    }

    pub const fn into_inner(self) -> [u8; UDOT_HASH_LEN] {
        self.0
    }

    pub fn to_lower_hex(&self) -> String {
        encode_lower_hex(&self.0)
    }
}

impl From<[u8; UDOT_HASH_LEN]> for AuraHashBytes {
    fn from(bytes: [u8; UDOT_HASH_LEN]) -> Self {
        Self::new(bytes)
    }
}

impl AsRef<[u8; UDOT_HASH_LEN]> for AuraHashBytes {
    fn as_ref(&self) -> &[u8; UDOT_HASH_LEN] {
        self.as_bytes()
    }
}

impl fmt::Display for AuraHashBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_lower_hex())
    }
}

fn decode_hex_nibble(value: char) -> Option<u8> {
    match value {
        '0'..='9' => Some(value as u8 - b'0'),
        'a'..='f' => Some(value as u8 - b'a' + 10),
        'A'..='F' => Some(value as u8 - b'A' + 10),
        _ => None,
    }
}

fn encode_lower_hex(bytes: &[u8; UDOT_HASH_LEN]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut output = String::with_capacity(UDOT_HASH_HEX_LEN);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
