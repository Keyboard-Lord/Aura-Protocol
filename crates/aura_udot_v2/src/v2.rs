use crate::{
    sha256_domain_separated, AuraHashBytes, CrestV2, MatrixFormV2, MatrixSequenceV2, SealLineV2,
    UdotParseError, UdotVersion, AURA_UDOT_SEAL_DOMAIN_SEPARATOR_V1,
    AURA_UDOT_SEAL_LINE_DOMAIN_SEPARATOR_V1, UDOT_DIGEST_LEN,
};
use core::str::FromStr;

const V2_GLYPHS: [char; 16] = [
    '◦', '◌', '∘', '○', '⟡', '◎', '•', '∙', '◈', '◇', '◆', 'ㅁ', '■', '□', '▣', '▤',
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdotV2Artifacts {
    pub format_version: UdotVersion,
    pub aura_hash_bytes: AuraHashBytes,
    pub seal_line: SealLineV2,
    pub crest: CrestV2,
    pub matrix_sequence: MatrixSequenceV2,
    pub matrix_form: MatrixFormV2,
}

pub fn derive_udot_v2(aura_hash_bytes: AuraHashBytes) -> UdotV2Artifacts {
    let line_digest =
        sha256_domain_separated(AURA_UDOT_SEAL_LINE_DOMAIN_SEPARATOR_V1, aura_hash_bytes);
    let crest_digest = sha256_domain_separated(AURA_UDOT_SEAL_DOMAIN_SEPARATOR_V1, aura_hash_bytes);

    let seal_line = SealLineV2::from_canonical(map_nibbles_to_v2_glyphs(&line_digest, 16));
    let crest = CrestV2::from_canonical(map_nibbles_to_v2_glyphs(&crest_digest, 8));
    let matrix_sequence = derive_wallet_sequence_v1(aura_hash_bytes);
    let matrix_form = derive_wallet_visual_v1(aura_hash_bytes);

    UdotV2Artifacts {
        format_version: UdotVersion::V2,
        aura_hash_bytes,
        seal_line,
        crest,
        matrix_sequence,
        matrix_form,
    }
}

pub fn derive_wallet_sequence_v1(aura_hash_bytes: AuraHashBytes) -> MatrixSequenceV2 {
    MatrixSequenceV2::from_canonical(map_hash_nibbles_to_v2_glyphs(aura_hash_bytes.as_bytes()))
}

pub fn derive_wallet_visual_v1(aura_hash_bytes: AuraHashBytes) -> MatrixFormV2 {
    let sequence = derive_wallet_sequence_v1(aura_hash_bytes);
    MatrixFormV2::from_canonical(matrix_form_from_sequence(sequence.as_str()))
}

pub fn aura_hash_from_wallet_sequence_v1(
    matrix_sequence: &str,
) -> Result<AuraHashBytes, UdotParseError> {
    let parsed = MatrixSequenceV2::from_str(matrix_sequence)?;
    Ok(decode_v2_glyphs_to_hash(parsed.as_str()))
}

pub fn aura_hash_from_wallet_visual_v1(
    wallet_visual_v1: &str,
) -> Result<AuraHashBytes, UdotParseError> {
    let parsed = MatrixFormV2::from_str(wallet_visual_v1)?;
    Ok(decode_v2_glyphs_to_hash(
        &parsed.as_str().lines().collect::<String>(),
    ))
}

fn map_nibbles_to_v2_glyphs(digest: &[u8; UDOT_DIGEST_LEN], glyph_count: usize) -> String {
    let mut output = String::with_capacity(glyph_count * 3);
    for glyph_index in 0..glyph_count {
        let byte = digest[glyph_index / 2];
        let nibble = if glyph_index % 2 == 0 {
            byte >> 4
        } else {
            byte & 0x0f
        };
        output.push(V2_GLYPHS[nibble as usize]);
    }
    output
}

fn map_hash_nibbles_to_v2_glyphs(aura_hash_bytes: &[u8; UDOT_DIGEST_LEN]) -> String {
    map_nibbles_to_v2_glyphs(aura_hash_bytes, 64)
}

fn decode_v2_glyphs_to_hash(sequence: &str) -> AuraHashBytes {
    let mut bytes = [0u8; UDOT_DIGEST_LEN];

    for (glyph_index, glyph) in sequence.chars().enumerate() {
        let nibble = V2_GLYPHS
            .iter()
            .position(|candidate| *candidate == glyph)
            .expect("validated V2 glyph");
        let byte = &mut bytes[glyph_index / 2];
        if glyph_index % 2 == 0 {
            *byte = (nibble as u8) << 4;
        } else {
            *byte |= nibble as u8;
        }
    }

    AuraHashBytes::new(bytes)
}

fn matrix_form_from_sequence(sequence: &str) -> String {
    let glyphs: Vec<char> = sequence.chars().collect();
    let mut output = String::with_capacity(sequence.len() + 7);
    for row_index in 0..8 {
        if row_index > 0 {
            output.push('\n');
        }

        let start = row_index * 8;
        let end = start + 8;
        for glyph in &glyphs[start..end] {
            output.push(*glyph);
        }
    }
    output
}
