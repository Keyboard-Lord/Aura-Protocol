use crate::{
    sha256_domain_separated, AuraHashBytes, CrestV1, SealLineV1, UdotVersion,
    AURA_UDOT_SEAL_DOMAIN_SEPARATOR_V1, AURA_UDOT_SEAL_LINE_DOMAIN_SEPARATOR_V1, UDOT_DIGEST_LEN,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdotLegacyV1Artifacts {
    pub format_version: UdotVersion,
    pub aura_hash_bytes: AuraHashBytes,
    pub seal_line: SealLineV1,
    pub crest: CrestV1,
}

pub fn derive_udot_v1_legacy(aura_hash_bytes: AuraHashBytes) -> UdotLegacyV1Artifacts {
    let line_digest =
        sha256_domain_separated(AURA_UDOT_SEAL_LINE_DOMAIN_SEPARATOR_V1, aura_hash_bytes);
    let crest_digest = sha256_domain_separated(AURA_UDOT_SEAL_DOMAIN_SEPARATOR_V1, aura_hash_bytes);

    let seal_line = SealLineV1::from_canonical(map_triplets_to_v1_glyphs(&line_digest, 16));
    let crest = CrestV1::from_canonical(map_triplets_to_v1_glyphs(&crest_digest, 8));

    UdotLegacyV1Artifacts {
        format_version: UdotVersion::V1Legacy,
        aura_hash_bytes,
        seal_line,
        crest,
    }
}

fn map_triplets_to_v1_glyphs(digest: &[u8; UDOT_DIGEST_LEN], group_count: usize) -> String {
    const V1_GLYPHS: [char; 8] = ['∘', '•', '∙', '⟡', '◦', '◎', '○', '◌'];

    let mut output = String::with_capacity(group_count * 3);
    for group_index in 0..group_count {
        let mut value = 0u8;
        let start_bit = group_index * 3;
        for offset in 0..3 {
            let bit_index = start_bit + offset;
            let byte = digest[bit_index / 8];
            let shift = 7 - (bit_index % 8);
            value = (value << 1) | ((byte >> shift) & 1);
        }
        output.push(V1_GLYPHS[value as usize]);
    }
    output
}
