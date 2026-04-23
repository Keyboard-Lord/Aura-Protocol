use core::{fmt, str::FromStr};
use serde::{Deserialize, Serialize};

pub const UDOT_V1_LEGACY_SPEC_VERSION: u8 = 1;
pub const UDOT_V2_SPEC_VERSION: u8 = 2;

const V1_GLYPHS: [char; 8] = ['∘', '•', '∙', '⟡', '◦', '◎', '○', '◌'];
const V2_GLYPHS: [char; 16] = [
    '◦', '◌', '∘', '○', '⟡', '◎', '•', '∙', '◈', '◇', '◆', 'ㅁ', '■', '□', '▣', '▤',
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UdotVersion {
    V1Legacy,
    V2,
}

impl UdotVersion {
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::V1Legacy => UDOT_V1_LEGACY_SPEC_VERSION,
            Self::V2 => UDOT_V2_SPEC_VERSION,
        }
    }
}

impl fmt::Display for UdotVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V1Legacy => write!(f, "UDOT V1 legacy"),
            Self::V2 => write!(f, "UDOT V2"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UdotArtifactKind {
    SealLine,
    Crest,
    MatrixSequence,
    MatrixForm,
}

impl fmt::Display for UdotArtifactKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SealLine => write!(f, "seal_line"),
            Self::Crest => write!(f, "crest"),
            Self::MatrixSequence => write!(f, "matrix_sequence"),
            Self::MatrixForm => write!(f, "matrix_form"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UdotParseError {
    UnsupportedArtifactForVersion {
        version: UdotVersion,
        kind: UdotArtifactKind,
    },
    InvalidLength {
        version: UdotVersion,
        kind: UdotArtifactKind,
        expected: usize,
        actual: usize,
    },
    InvalidWhitespace {
        version: UdotVersion,
        kind: UdotArtifactKind,
        index: usize,
        value: char,
    },
    InvalidGlyph {
        version: UdotVersion,
        kind: UdotArtifactKind,
        index: usize,
        value: char,
    },
    InvalidMatrixRowCount {
        expected: usize,
        actual: usize,
    },
    InvalidMatrixRowLength {
        row: usize,
        expected: usize,
        actual: usize,
    },
}

impl fmt::Display for UdotParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedArtifactForVersion { version, kind } => {
                write!(f, "{kind} is not defined for {version}")
            }
            Self::InvalidLength {
                version,
                kind,
                expected,
                actual,
            } => write!(
                f,
                "invalid {kind} length for {version}: expected {expected}, got {actual}"
            ),
            Self::InvalidWhitespace {
                version,
                kind,
                index,
                value,
            } => write!(
                f,
                "invalid whitespace in {kind} for {version} at index {index}: {value:?}"
            ),
            Self::InvalidGlyph {
                version,
                kind,
                index,
                value,
            } => write!(
                f,
                "invalid glyph in {kind} for {version} at index {index}: {value:?}"
            ),
            Self::InvalidMatrixRowCount { expected, actual } => write!(
                f,
                "invalid matrix_form row count: expected {expected}, got {actual}"
            ),
            Self::InvalidMatrixRowLength {
                row,
                expected,
                actual,
            } => write!(
                f,
                "invalid matrix_form row length at row {row}: expected {expected}, got {actual}"
            ),
        }
    }
}

impl std::error::Error for UdotParseError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UdotValidationError {
    Parse(UdotParseError),
    Mismatch {
        version: UdotVersion,
        kind: UdotArtifactKind,
        expected: String,
        actual: String,
    },
}

impl fmt::Display for UdotValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(error) => write!(f, "{error}"),
            Self::Mismatch {
                version,
                kind,
                expected,
                actual,
            } => write!(
                f,
                "{kind} mismatch for {version}: expected {expected:?}, got {actual:?}"
            ),
        }
    }
}

impl std::error::Error for UdotValidationError {}

impl From<UdotParseError> for UdotValidationError {
    fn from(error: UdotParseError) -> Self {
        Self::Parse(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SealLineV1(String);

impl SealLineV1 {
    pub(crate) fn from_canonical(inner: String) -> Self {
        Self(inner)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SealLineV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for SealLineV1 {
    type Err = UdotParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Ok(Self(parse_sequence(
            UdotVersion::V1Legacy,
            UdotArtifactKind::SealLine,
            input,
            16,
        )?))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CrestV1(String);

impl CrestV1 {
    pub(crate) fn from_canonical(inner: String) -> Self {
        Self(inner)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CrestV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for CrestV1 {
    type Err = UdotParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Ok(Self(parse_sequence(
            UdotVersion::V1Legacy,
            UdotArtifactKind::Crest,
            input,
            8,
        )?))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SealLineV2(String);

impl SealLineV2 {
    pub(crate) fn from_canonical(inner: String) -> Self {
        Self(inner)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SealLineV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for SealLineV2 {
    type Err = UdotParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Ok(Self(parse_sequence(
            UdotVersion::V2,
            UdotArtifactKind::SealLine,
            input,
            16,
        )?))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CrestV2(String);

impl CrestV2 {
    pub(crate) fn from_canonical(inner: String) -> Self {
        Self(inner)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CrestV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for CrestV2 {
    type Err = UdotParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Ok(Self(parse_sequence(
            UdotVersion::V2,
            UdotArtifactKind::Crest,
            input,
            8,
        )?))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MatrixSequenceV2(String);

impl MatrixSequenceV2 {
    pub(crate) fn from_canonical(inner: String) -> Self {
        Self(inner)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MatrixSequenceV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for MatrixSequenceV2 {
    type Err = UdotParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Ok(Self(parse_sequence(
            UdotVersion::V2,
            UdotArtifactKind::MatrixSequence,
            input,
            64,
        )?))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MatrixFormV2(String);

impl MatrixFormV2 {
    pub(crate) fn from_canonical(inner: String) -> Self {
        Self(inner)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MatrixFormV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for MatrixFormV2 {
    type Err = UdotParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Ok(Self(parse_matrix_form(input)?))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParsedUdotArtifact {
    SealLineV1(SealLineV1),
    CrestV1(CrestV1),
    SealLineV2(SealLineV2),
    CrestV2(CrestV2),
    MatrixSequenceV2(MatrixSequenceV2),
    MatrixFormV2(MatrixFormV2),
}

impl ParsedUdotArtifact {
    pub fn version(&self) -> UdotVersion {
        match self {
            Self::SealLineV1(_) | Self::CrestV1(_) => UdotVersion::V1Legacy,
            Self::SealLineV2(_)
            | Self::CrestV2(_)
            | Self::MatrixSequenceV2(_)
            | Self::MatrixFormV2(_) => UdotVersion::V2,
        }
    }

    pub fn kind(&self) -> UdotArtifactKind {
        match self {
            Self::SealLineV1(_) | Self::SealLineV2(_) => UdotArtifactKind::SealLine,
            Self::CrestV1(_) | Self::CrestV2(_) => UdotArtifactKind::Crest,
            Self::MatrixSequenceV2(_) => UdotArtifactKind::MatrixSequence,
            Self::MatrixFormV2(_) => UdotArtifactKind::MatrixForm,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::SealLineV1(value) => value.as_str(),
            Self::CrestV1(value) => value.as_str(),
            Self::SealLineV2(value) => value.as_str(),
            Self::CrestV2(value) => value.as_str(),
            Self::MatrixSequenceV2(value) => value.as_str(),
            Self::MatrixFormV2(value) => value.as_str(),
        }
    }
}

impl fmt::Display for ParsedUdotArtifact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

pub fn parse_udot_artifact(
    version: UdotVersion,
    kind: UdotArtifactKind,
    input: &str,
) -> Result<ParsedUdotArtifact, UdotParseError> {
    match (version, kind) {
        (UdotVersion::V1Legacy, UdotArtifactKind::SealLine) => {
            Ok(ParsedUdotArtifact::SealLineV1(SealLineV1::from_str(input)?))
        }
        (UdotVersion::V1Legacy, UdotArtifactKind::Crest) => {
            Ok(ParsedUdotArtifact::CrestV1(CrestV1::from_str(input)?))
        }
        (UdotVersion::V2, UdotArtifactKind::SealLine) => {
            Ok(ParsedUdotArtifact::SealLineV2(SealLineV2::from_str(input)?))
        }
        (UdotVersion::V2, UdotArtifactKind::Crest) => {
            Ok(ParsedUdotArtifact::CrestV2(CrestV2::from_str(input)?))
        }
        (UdotVersion::V2, UdotArtifactKind::MatrixSequence) => Ok(
            ParsedUdotArtifact::MatrixSequenceV2(MatrixSequenceV2::from_str(input)?),
        ),
        (UdotVersion::V2, UdotArtifactKind::MatrixForm) => Ok(ParsedUdotArtifact::MatrixFormV2(
            MatrixFormV2::from_str(input)?,
        )),
        (version, kind) => Err(UdotParseError::UnsupportedArtifactForVersion { version, kind }),
    }
}

fn parse_sequence(
    version: UdotVersion,
    kind: UdotArtifactKind,
    input: &str,
    expected_len: usize,
) -> Result<String, UdotParseError> {
    let actual_len = input.chars().count();
    if actual_len != expected_len {
        return Err(UdotParseError::InvalidLength {
            version,
            kind,
            expected: expected_len,
            actual: actual_len,
        });
    }

    for (index, value) in input.chars().enumerate() {
        if value.is_whitespace() {
            return Err(UdotParseError::InvalidWhitespace {
                version,
                kind,
                index,
                value,
            });
        }

        let is_allowed = match version {
            UdotVersion::V1Legacy => V1_GLYPHS.contains(&value),
            UdotVersion::V2 => V2_GLYPHS.contains(&value),
        };

        if !is_allowed {
            return Err(UdotParseError::InvalidGlyph {
                version,
                kind,
                index,
                value,
            });
        }
    }

    Ok(input.to_owned())
}

fn parse_matrix_form(input: &str) -> Result<String, UdotParseError> {
    for (index, value) in input.chars().enumerate() {
        if value.is_whitespace() && value != '\n' {
            return Err(UdotParseError::InvalidWhitespace {
                version: UdotVersion::V2,
                kind: UdotArtifactKind::MatrixForm,
                index,
                value,
            });
        }
    }

    let rows: Vec<&str> = input.split('\n').collect();
    if rows.len() != 8 {
        return Err(UdotParseError::InvalidMatrixRowCount {
            expected: 8,
            actual: rows.len(),
        });
    }

    for (row_index, row) in rows.iter().enumerate() {
        let actual_len = row.chars().count();
        if actual_len != 8 {
            return Err(UdotParseError::InvalidMatrixRowLength {
                row: row_index,
                expected: 8,
                actual: actual_len,
            });
        }

        for (column_index, value) in row.chars().enumerate() {
            if !V2_GLYPHS.contains(&value) {
                return Err(UdotParseError::InvalidGlyph {
                    version: UdotVersion::V2,
                    kind: UdotArtifactKind::MatrixForm,
                    index: (row_index * 9) + column_index,
                    value,
                });
            }
        }
    }

    Ok(input.to_owned())
}
