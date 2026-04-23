//! Manual Pipeline Walk Test — Multi-Mode Protocol Observability Tool
//!
//! Modes:
//!   --full     : Complete forensic trace (default)
//!   --compact  : Summary of key stages only
//!   --diff     : Compare two inputs side-by-side
//!
//! Run with:
//!   cargo test -p aura_intent_lineage_v1 --test manual_pipeline_walk_v1 -- --nocapture
//!   cargo test -p aura_intent_lineage_v1 --test manual_pipeline_walk_v1 -- --nocapture -- --compact
//!   cargo test -p aura_intent_lineage_v1 --test manual_pipeline_walk_v1 -- --nocapture -- --diff variant_a variant_b

use std::env;
use std::fs;
use std::path::Path;

use aura_intent_lineage_v1::{
    build_storm_claim_v1, build_storm_public_inputs_v1, build_storm_trace_witness_v1,
    compute_storm_trace_root, derive_a, derive_b, derive_phi_n,
    derive_psi_n, derive_x0, derive_y0, execute_storm_v1, storm_leaf_hash,
    FieldElement521V1, StormClaim521V1, StormContextV1, StormExecutionInputsV1,
    StormState521V1, StormTraceRootV1, STORM_CONTEXT_V1_LEN, STORM_CONTEXT_V1_VERSION,
    STORM_SIDE_INPUT_LEN_V1, FIELD_ELEMENT_521_BYTE_LEN_V1, STORM_STATE_521_ROW_BYTE_LEN_V1,
    AURA_X0_V1_DOMAIN_SEPARATOR, AURA_Y0_V1_DOMAIN_SEPARATOR,
    AURA_C_A_V1_DOMAIN_SEPARATOR, AURA_C_B_V1_DOMAIN_SEPARATOR,
    AURA_STORM_X_V1_DOMAIN_SEPARATOR, AURA_STORM_Y_V1_DOMAIN_SEPARATOR,
};
use aura_udot_v2::{derive_udot_v2, AuraHashBytes as UdotAuraHashBytes};
use sha3::{Digest, Sha3_256, Sha3_512};

// =============================================================================
// EXECUTION MODES
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutionMode {
    Full,
    Compact,
    Diff { fixture_a: &'static str, fixture_b: &'static str },
}

impl ExecutionMode {
    fn from_args(args: &[String]) -> Self {
        for (i, arg) in args.iter().enumerate() {
            match arg.as_str() {
                "--compact" => return ExecutionMode::Compact,
                "--full" => return ExecutionMode::Full,
                "--diff" => {
                    let fixture_a = Box::leak(args.get(i + 1).cloned().unwrap_or_else(|| "default".to_string()).into_boxed_str());
                    let fixture_b = Box::leak(args.get(i + 2).cloned().unwrap_or_else(|| "variant".to_string()).into_boxed_str());
                    return ExecutionMode::Diff { fixture_a, fixture_b };
                }
                _ => continue,
            }
        }
        ExecutionMode::Full
    }
}

// =============================================================================
// PIPELINE SNAPSHOT
// =============================================================================

#[derive(Debug, Clone)]
struct PipelineSnapshot {
    name: String,
    side_a: [u8; STORM_SIDE_INPUT_LEN_V1],
    side_b: [u8; STORM_SIDE_INPUT_LEN_V1],
    context_bytes: [u8; STORM_CONTEXT_V1_LEN],
    iteration_count: u64,
    x0: FieldElement521V1,
    y0: FieldElement521V1,
    a: FieldElement521V1,
    b: FieldElement521V1,
    phi_0: FieldElement521V1,
    psi_0: FieldElement521V1,
    state_0: StormState521V1,
    state_1: StormState521V1,
    final_state: StormState521V1,
    trace: Vec<StormState521V1>,
    trace_root: [u8; 32],
    side_a_hash: [u8; 32],
    side_b_hash: [u8; 32],
    context_hash: [u8; 32],
    seal_line: String,
    crest: String,
    matrix_form: String,
}

// =============================================================================
// TEST FIXTURES
// =============================================================================

const TEST_SIDE_A: [u8; STORM_SIDE_INPUT_LEN_V1] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
    0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32,
    0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
    0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
    0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a,
    0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64,
    0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
];

const TEST_SIDE_B: [u8; STORM_SIDE_INPUT_LEN_V1] = [
    0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a,
    0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84,
    0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
    0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
    0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2,
    0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac,
    0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6,
    0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0,
    0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca,
    0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4,
    0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde,
];

const TEST_SIDE_A_VARIANT: [u8; STORM_SIDE_INPUT_LEN_V1] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
    0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32,
    0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
    0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
    0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a,
    0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64,
    0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6f,
];

const TEST_SIDE_B_VARIANT: [u8; STORM_SIDE_INPUT_LEN_V1] = [
    0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6,
    0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0, 0xef, 0xee, 0xed, 0xec,
    0xeb, 0xea, 0xe9, 0xe8, 0xe7, 0xe6, 0xe5, 0xe4, 0xe3, 0xe2,
    0xe1, 0xe0, 0xdf, 0xde, 0xdd, 0xdc, 0xdb, 0xda, 0xd9, 0xd8,
    0xd7, 0xd6, 0xd5, 0xd4, 0xd3, 0xd2, 0xd1, 0xd0, 0xcf, 0xce,
    0xcd, 0xcc, 0xcb, 0xca, 0xc9, 0xc8, 0xc7, 0xc6, 0xc5, 0xc4,
    0xc3, 0xc2, 0xc1, 0xc0, 0xbf, 0xbe, 0xbd, 0xbc, 0xbb, 0xba,
    0xb9, 0xb8, 0xb7, 0xb6, 0xb5, 0xb4, 0xb3, 0xb2, 0xb1, 0xb0,
    0xaf, 0xae, 0xad, 0xac, 0xab, 0xaa, 0xa9, 0xa8, 0xa7, 0xa6,
    0xa5, 0xa4, 0xa3, 0xa2, 0xa1, 0xa0, 0x9f, 0x9e, 0x9d, 0x9c,
    0x9b, 0x9a, 0x99, 0x98, 0x97, 0x96, 0x95, 0x94, 0x93, 0x92,
];

fn make_test_context() -> [u8; STORM_CONTEXT_V1_LEN] {
    StormContextV1 {
        context_version: STORM_CONTEXT_V1_VERSION,
        network_id: [
            0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
            0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
        ],
        intent_hash: [
            0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
            0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        ],
        freshness_nonce: [
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
            0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0,
            0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
        ],
        valid_from: 1000,
        valid_until: 5000,
        controller_id: [
            0x98, 0x87, 0x76, 0x65, 0x54, 0x43, 0x32, 0x21,
            0x10, 0x0f, 0xfe, 0xed, 0xdc, 0xcb, 0xba, 0xa9,
            0x87, 0x65, 0x43, 0x21, 0x10, 0xfe, 0xdc, 0xba,
            0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba,
        ],
        route_tag: [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
            0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
        ],
    }
    .to_bytes()
}

fn get_fixture(name: &str) -> ([u8; STORM_SIDE_INPUT_LEN_V1], [u8; STORM_SIDE_INPUT_LEN_V1]) {
    match name {
        "variant_a" | "fixture_a" => (TEST_SIDE_A_VARIANT, TEST_SIDE_B),
        "variant_b" | "fixture_b" => (TEST_SIDE_A, TEST_SIDE_B_VARIANT),
        _ => (TEST_SIDE_A, TEST_SIDE_B),
    }
}

// =============================================================================
// UTILITIES
// =============================================================================

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn field_to_hex(f: &FieldElement521V1) -> String {
    bytes_to_hex(&f.to_bytes())
}

fn print_separator(title: &str) {
    let width: usize = 70;
    let pad = (width.saturating_sub(title.len())) / 2;
    let line = "=".repeat(width);
    let padding = " ".repeat(pad);
    println!("\n{}", line);
    println!("{}{}", padding, title);
    println!("{}", line);
}

fn print_stage(stage_num: u8, stage_name: &str, purpose: &str) {
    println!("\n>>> STAGE {:02}: {}", stage_num, stage_name);
    println!("    Purpose: {}", purpose);
    println!("    {}", "-".repeat(66));
}

fn print_bytes(name: &str, bytes: &[u8], max_show: usize) {
    let hex = bytes_to_hex(bytes);
    if bytes.len() <= max_show * 2 {
        println!("    {}: {} bytes", name, bytes.len());
        println!("         hex: {}", hex);
    } else {
        let show_len = max_show.min(bytes.len());
        println!("    {}: {} bytes", name, bytes.len());
        println!("         hex (first {} bytes): {}", show_len, &hex[..show_len * 2]);
        println!("         ... (truncated, full in report)");
    }
}

fn print_field(name: &str, f: &FieldElement521V1) {
    println!("    {}:", name);
    println!("         hex: {}", field_to_hex(f));
    let bytes = f.to_bytes();
    let mut val = 0u128;
    for (_, byte) in bytes.iter().enumerate().take(16) {
        val = (val << 8) | (*byte as u128);
    }
    println!("         int: {}... (top 128 bits)", val);
    println!("         bytes: {}", FIELD_ELEMENT_521_BYTE_LEN_V1);
}

fn print_state(name: &str, state: &StormState521V1) {
    println!("    {}:", name);
    println!("         x: {}", field_to_hex(&state.x));
    println!("         y: {}", field_to_hex(&state.y));
}

fn print_hash32(name: &str, hash: &[u8; 32]) {
    println!("    {}: 32 bytes", name);
    println!("         hex: {}", bytes_to_hex(hash));
}

// =============================================================================
// PIPELINE EXECUTION
// =============================================================================

fn run_pipeline(
    name: &str,
    side_a: [u8; STORM_SIDE_INPUT_LEN_V1],
    side_b: [u8; STORM_SIDE_INPUT_LEN_V1],
    context_bytes: [u8; STORM_CONTEXT_V1_LEN],
    iteration_count: u64,
) -> PipelineSnapshot {
    let x0 = derive_x0(&side_a);
    let y0 = derive_y0(&side_b);
    let a = derive_a(&context_bytes);
    let b = derive_b(&context_bytes);

    let execution_inputs = StormExecutionInputsV1 {
        side_a,
        side_b,
        context_bytes_v1: context_bytes,
        iteration_count,
    };
    let execution = execute_storm_v1(&execution_inputs);

    let phi_0 = derive_phi_n(&side_a, &side_b, &context_bytes, 0);
    let psi_0 = derive_psi_n(&side_a, &side_b, &context_bytes, 0);

    let trace_root = compute_storm_trace_root(&execution.trace);

    let intent_hash = [0x11u8; 32];
    let lineage_hash = [0x22u8; 32];
    let storm_claim = build_storm_claim_v1(&execution_inputs, intent_hash, lineage_hash);
    let public_inputs = build_storm_public_inputs_v1(&storm_claim);

    let final_aura_hash = UdotAuraHashBytes::new(trace_root);
    let udot_artifacts = derive_udot_v2(final_aura_hash);

    PipelineSnapshot {
        name: name.to_string(),
        side_a,
        side_b,
        context_bytes,
        iteration_count,
        x0,
        y0,
        a,
        b,
        phi_0,
        psi_0,
        state_0: execution.initial_state,
        state_1: execution.trace.get(1).copied().unwrap_or(execution.final_state),
        final_state: execution.final_state,
        trace: execution.trace.clone(),
        trace_root,
        side_a_hash: public_inputs.side_a_hash,
        side_b_hash: public_inputs.side_b_hash,
        context_hash: public_inputs.context_hash,
        seal_line: udot_artifacts.seal_line.as_str().to_string(),
        crest: udot_artifacts.crest.as_str().to_string(),
        matrix_form: udot_artifacts.matrix_form.as_str().to_string(),
    }
}

// =============================================================================
// OUTPUT MODES
// =============================================================================

fn output_compact(snapshot: &PipelineSnapshot) {
    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║           AURA PIPELINE WALK — COMPACT MODE                      ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");

    println!("\n📋 Input Summary");
    println!("   Side A: {} bytes | Side B: {} bytes | Iterations: {}",
        snapshot.side_a.len(), snapshot.side_b.len(), snapshot.iteration_count);
    println!("   Side A hash: {}", &bytes_to_hex(&snapshot.side_a_hash)[..32]);

    println!("\n🔐 H_521 Init State");
    println!("   x0: {}...", &field_to_hex(&snapshot.x0)[..32]);
    println!("   y0: {}...", &field_to_hex(&snapshot.y0)[..32]);
    println!("   a:  {}...", &field_to_hex(&snapshot.a)[..24]);
    println!("   b:  {}...", &field_to_hex(&snapshot.b)[..24]);

    println!("\n⚡ First STORM Step");
    println!("   phi_0: {}...", &field_to_hex(&snapshot.phi_0)[..24]);
    println!("   psi_0: {}...", &field_to_hex(&snapshot.psi_0)[..24]);
    println!("   state_0 -> state_1:");
    println!("     x: {}... -> {}...",
        &field_to_hex(&snapshot.state_0.x)[..16],
        &field_to_hex(&snapshot.state_1.x)[..16]);
    println!("     y: {}... -> {}...",
        &field_to_hex(&snapshot.state_0.y)[..16],
        &field_to_hex(&snapshot.state_1.y)[..16]);

    println!("\n🎯 Final State");
    println!("   x_final: {}...", &field_to_hex(&snapshot.final_state.x)[..32]);
    println!("   y_final: {}...", &field_to_hex(&snapshot.final_state.y)[..32]);

    println!("\n🔗 Trace Commitment");
    println!("   Trace root: {}", bytes_to_hex(&snapshot.trace_root));
    println!("   States: {} | Leaves: {}", snapshot.trace.len(), snapshot.trace.len());

    println!("\n📦 Binding (Public Inputs Hash)");
    let binding_preimage = [
        snapshot.side_a_hash.as_slice(),
        snapshot.side_b_hash.as_slice(),
        snapshot.context_hash.as_slice(),
        snapshot.trace_root.as_slice(),
    ].concat();
    let binding_digest = Sha3_256::digest(&binding_preimage);
    let binding_arr: [u8; 32] = binding_digest.into();
    println!("   Binding digest: {}", bytes_to_hex(&binding_arr));

    println!("\n🎨 UDOT Artifacts");
    println!("   Seal: {}", snapshot.seal_line);
    println!("   Crest: {}", snapshot.crest);
    println!("   Matrix (first line): {}", snapshot.matrix_form.lines().next().unwrap_or(""));

    println!("\n✅ Compact summary complete");
}

fn output_full(snapshot: &PipelineSnapshot) {
    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║     AURA MANUAL PIPELINE WALK — FULL FORENSIC MODE               ║");
    println!("║     Test Vector: {}                                     ║", snapshot.name);
    println!("╚══════════════════════════════════════════════════════════════════╝");

    print_stage(1, "ORIGINAL INPUT", "Show the raw test inputs before any transformation");
    println!("    Side A (110 bytes):");
    println!("         hex: {}", &bytes_to_hex(&snapshot.side_a)[..64]);
    println!("         ... (full: {:} bytes)", snapshot.side_a.len());
    println!("    Side B (110 bytes):");
    println!("         hex: {}", &bytes_to_hex(&snapshot.side_b)[..64]);
    println!("         ... (full: {:} bytes)", snapshot.side_b.len());
    print_bytes("Context bytes", &snapshot.context_bytes, 32);
    println!("    Iteration count: {}", snapshot.iteration_count);

    print_stage(2, "H_521 DOMAIN-SEPARATED DERIVATIONS",
        "Show how x0, y0, a, b are derived via domain-separated H_521 hashing");
    println!("    Deriving x0:");
    println!("         Domain separator: {:?}", AURA_X0_V1_DOMAIN_SEPARATOR);
    print_field("    x0 (H_521 reduced)", &snapshot.x0);
    println!("    Deriving y0:");
    println!("         Domain separator: {:?}", AURA_Y0_V1_DOMAIN_SEPARATOR);
    print_field("    y0 (H_521 reduced)", &snapshot.y0);
    println!("    Deriving a:");
    println!("         Domain separator: {:?}", AURA_C_A_V1_DOMAIN_SEPARATOR);
    print_field("    a (H_521 reduced)", &snapshot.a);
    println!("    Deriving b:");
    println!("         Domain separator: {:?}", AURA_C_B_V1_DOMAIN_SEPARATOR);
    print_field("    b (H_521 reduced)", &snapshot.b);

    print_stage(5, "STORM EXECUTION", "Execute the quadratic recurrence");
    print_state("    Initial state", &snapshot.state_0);
    println!("\n    --- Step 0 (first injection) ---");
    print_field("    phi_0", &snapshot.phi_0);
    print_field("    psi_0", &snapshot.psi_0);
    print_state("    State after step 0", &snapshot.state_1);
    print_stage(6, "STORM FINAL STATE", "Result after all iterations");
    print_state("    Final state", &snapshot.final_state);
    println!("    Trace length: {} states", snapshot.trace.len());

    print_stage(7, "TRACE ENCODING & MERKLE TREE", "Build trace commitment");
    println!("    Row encoding: x_bytes || y_bytes (132 bytes per row)");
    println!("    Leaves: {} (one per state)", snapshot.trace.len());
    print_hash32("    Trace root", &snapshot.trace_root);

    print_stage(10, "STORM CLAIM", "Canonical claim with all fields");
    println!("    Side A hash: {}", &bytes_to_hex(&snapshot.side_a_hash)[..64]);
    println!("    Side B hash: {}", &bytes_to_hex(&snapshot.side_b_hash)[..64]);
    println!("    Context hash: {}", &bytes_to_hex(&snapshot.context_hash)[..64]);
    print_hash32("    Trace root", &snapshot.trace_root);

    print_stage(14, "UDOT CONSTRUCTION", "Visual artifacts from final hash");
    println!("    Seal Line: {}", snapshot.seal_line);
    println!("    Crest: {}", snapshot.crest);
    println!("    Matrix:");
    for line in snapshot.matrix_form.lines().take(8) {
        println!("         {}", line);
    }

    print_separator("PIPELINE WALK COMPLETE");
    println!("\nKey Artifacts:");
    println!("    Initial x0: {}...", &field_to_hex(&snapshot.x0)[..32]);
    println!("    Final x:    {}...", &field_to_hex(&snapshot.final_state.x)[..32]);
    print_hash32("    Trace root", &snapshot.trace_root);
    println!("    UDOT Seal:  {}", snapshot.seal_line);
}

fn output_diff(snap_a: &PipelineSnapshot, snap_b: &PipelineSnapshot) {
    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║           AURA PIPELINE WALK — DIFF MODE                         ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");

    fn compare_field(name: &str, a: &str, b: &str) {
        let equal = a == b;
        let status = if equal { "✅ EQUAL" } else { "❌ DIFF" };
        println!("\n[{}] {}", status, name);
        if !equal {
            println!("    A: {}", a);
            println!("    B: {}", b);
        }
    }

    println!("\n🔍 Comparing: '{}' vs '{}'", snap_a.name, snap_b.name);

    compare_field("Side A Input",
        &bytes_to_hex(&snap_a.side_a[..16]),
        &bytes_to_hex(&snap_b.side_a[..16]));
    compare_field("Side B Input",
        &bytes_to_hex(&snap_a.side_b[..16]),
        &bytes_to_hex(&snap_b.side_b[..16]));

    compare_field("x0 (H_521)", &field_to_hex(&snap_a.x0), &field_to_hex(&snap_b.x0));
    compare_field("y0 (H_521)", &field_to_hex(&snap_a.y0), &field_to_hex(&snap_b.y0));
    compare_field("a (H_521)", &field_to_hex(&snap_a.a), &field_to_hex(&snap_b.a));
    compare_field("b (H_521)", &field_to_hex(&snap_a.b), &field_to_hex(&snap_b.b));

    compare_field("phi_0", &field_to_hex(&snap_a.phi_0), &field_to_hex(&snap_b.phi_0));
    compare_field("psi_0", &field_to_hex(&snap_a.psi_0), &field_to_hex(&snap_b.psi_0));
    compare_field("state_0.x", &field_to_hex(&snap_a.state_0.x), &field_to_hex(&snap_b.state_0.x));
    compare_field("state_0.y", &field_to_hex(&snap_a.state_0.y), &field_to_hex(&snap_b.state_0.y));
    compare_field("state_1.x", &field_to_hex(&snap_a.state_1.x), &field_to_hex(&snap_b.state_1.x));
    compare_field("state_1.y", &field_to_hex(&snap_a.state_1.y), &field_to_hex(&snap_b.state_1.y));

    compare_field("final_state.x", &field_to_hex(&snap_a.final_state.x), &field_to_hex(&snap_b.final_state.x));
    compare_field("final_state.y", &field_to_hex(&snap_a.final_state.y), &field_to_hex(&snap_b.final_state.y));

    compare_field("trace_root", &bytes_to_hex(&snap_a.trace_root), &bytes_to_hex(&snap_b.trace_root));
    compare_field("side_a_hash", &bytes_to_hex(&snap_a.side_a_hash), &bytes_to_hex(&snap_b.side_a_hash));

    compare_field("UDOT Seal", &snap_a.seal_line, &snap_b.seal_line);
    compare_field("UDOT Crest", &snap_a.crest, &snap_b.crest);

    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║                    DIFF ANALYSIS COMPLETE                        ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
}

// =============================================================================
// MARKDOWN REPORT GENERATORS
// =============================================================================

fn generate_compact_markdown(snapshot: &PipelineSnapshot) {
    let mut report = String::new();
    report.push_str("# AURA Pipeline Walk — Compact Mode\n\n");
    report.push_str(&format!("**Test Vector:** {}\n\n", snapshot.name));
    
    report.push_str("## Input Summary\n\n");
    report.push_str(&format!("- Side A: {} bytes\n", snapshot.side_a.len()));
    report.push_str(&format!("- Side B: {} bytes\n", snapshot.side_b.len()));
    report.push_str(&format!("- Iterations: {}\n\n", snapshot.iteration_count));
    
    report.push_str("## H_521 Init State\n\n");
    report.push_str(&format!("- x0: `{}`\n", field_to_hex(&snapshot.x0)));
    report.push_str(&format!("- y0: `{}`\n", field_to_hex(&snapshot.y0)));
    report.push_str(&format!("- a: `{}`\n", field_to_hex(&snapshot.a)));
    report.push_str(&format!("- b: `{}`\n\n", field_to_hex(&snapshot.b)));
    
    report.push_str("## First STORM Step\n\n");
    report.push_str(&format!("- phi_0: `{}`\n", field_to_hex(&snapshot.phi_0)));
    report.push_str(&format!("- psi_0: `{}`\n\n", field_to_hex(&snapshot.psi_0)));
    
    report.push_str("## Final State\n\n");
    report.push_str(&format!("- x_final: `{}`\n", field_to_hex(&snapshot.final_state.x)));
    report.push_str(&format!("- y_final: `{}`\n\n", field_to_hex(&snapshot.final_state.y)));
    
    report.push_str("## Trace Commitment\n\n");
    report.push_str(&format!("- Root: `{}`\n", bytes_to_hex(&snapshot.trace_root)));
    report.push_str(&format!("- States: {}\n\n", snapshot.trace.len()));
    
    report.push_str("## UDOT Artifacts\n\n");
    report.push_str(&format!("- Seal: `{}`\n", snapshot.seal_line));
    report.push_str(&format!("- Crest: `{}`\n\n", snapshot.crest));
    
    report.push_str("---\n\n✅ Compact summary complete\n");

    let reports_dir = Path::new("/Users/mcrae/Desktop/AURA/reports");
    if !reports_dir.exists() {
        let _ = fs::create_dir_all(reports_dir);
    }
    let report_path = reports_dir.join("AURA_MANUAL_PIPELINE_WALK_V1_COMPACT.md");
    fs::write(&report_path, report).expect("Failed to write compact report");
    println!("\n📄 Compact report: reports/AURA_MANUAL_PIPELINE_WALK_V1_COMPACT.md");
}

fn generate_diff_markdown(snap_a: &PipelineSnapshot, snap_b: &PipelineSnapshot) {
    let mut report = String::new();
    report.push_str("# AURA Pipeline Walk — Diff Mode\n\n");
    report.push_str(&format!("**Comparing:** {} vs {}\n\n", snap_a.name, snap_b.name));
    
    report.push_str("## Side-by-Side Comparison\n\n");
    report.push_str("| Stage | Fixture A | Fixture B | Equal |\n");
    report.push_str("|-------|-----------|-----------|-------|\n");
    
    fn row(name: &str, a: &str, b: &str, equal: bool) -> String {
        format!("| {} | `{}` | `{}` | {} |\n", name, a, b, if equal { "✅" } else { "❌" })
    }
    
    report.push_str(&row("x0", &field_to_hex(&snap_a.x0)[..32], &field_to_hex(&snap_b.x0)[..32], snap_a.x0 == snap_b.x0));
    report.push_str(&row("y0", &field_to_hex(&snap_a.y0)[..32], &field_to_hex(&snap_b.y0)[..32], snap_a.y0 == snap_b.y0));
    report.push_str(&row("phi_0", &field_to_hex(&snap_a.phi_0)[..32], &field_to_hex(&snap_b.phi_0)[..32], snap_a.phi_0 == snap_b.phi_0));
    report.push_str(&row("psi_0", &field_to_hex(&snap_a.psi_0)[..32], &field_to_hex(&snap_b.psi_0)[..32], snap_a.psi_0 == snap_b.psi_0));
    report.push_str(&row("trace_root", &bytes_to_hex(&snap_a.trace_root), &bytes_to_hex(&snap_b.trace_root), snap_a.trace_root == snap_b.trace_root));
    report.push_str(&row("UDOT Seal", &snap_a.seal_line, &snap_b.seal_line, snap_a.seal_line == snap_b.seal_line));
    
    report.push_str("\n---\n\n✅ Diff analysis complete\n");

    let reports_dir = Path::new("/Users/mcrae/Desktop/AURA/reports");
    if !reports_dir.exists() {
        let _ = fs::create_dir_all(reports_dir);
    }
    let report_path = reports_dir.join("AURA_MANUAL_PIPELINE_DIFF_V1.md");
    fs::write(&report_path, report).expect("Failed to write diff report");
    println!("\n📄 Diff report: reports/AURA_MANUAL_PIPELINE_DIFF_V1.md");
}

fn generate_full_markdown(snapshot: &PipelineSnapshot) {
    let mut report = String::new();
    report.push_str("# AURA Manual Pipeline Walk Report V1\n\n");
    report.push_str("**Generated by:** manual_pipeline_walk_v1 test\n");
    report.push_str("**Test Vector:** AURA_MANUAL_WALK_TEST_VECTOR_V1\n\n");
    report.push_str("---\n\n");
    
    report.push_str("## Stage 01: Original Input\n\n");
    report.push_str(&format!("### Side A (110 bytes)\n```\n{}\n```\n\n", bytes_to_hex(&snapshot.side_a[..32])));
    report.push_str(&format!("### Side B (110 bytes)\n```\n{}\n```\n\n", bytes_to_hex(&snapshot.side_b[..32])));
    report.push_str(&format!("### Iteration Count\n```\n{}\n```\n\n", snapshot.iteration_count));
    
    report.push_str("---\n\n");
    report.push_str("## Stage 02-04: H_521 Derivation and Init State\n\n");
    report.push_str(&format!("### x0 Derivation\n- **Domain Separator:** AURA_X0_V1\n- **H_521 reduced x0:**\n```\n{}\n```\n\n", field_to_hex(&snapshot.x0)));
    report.push_str(&format!("### y0 Derivation\n- **Domain Separator:** AURA_Y0_V1\n- **H_521 reduced y0:**\n```\n{}\n```\n\n", field_to_hex(&snapshot.y0)));
    report.push_str(&format!("### a Derivation\n```\n{}\n```\n\n", field_to_hex(&snapshot.a)));
    report.push_str(&format!("### b Derivation\n```\n{}\n```\n\n", field_to_hex(&snapshot.b)));
    
    report.push_str("---\n\n");
    report.push_str("## Stage 05-06: STORM Execution\n\n");
    report.push_str("### Recurrence Relation\n```\nx_{n+1} = x_n^2 - y_n^2 + a + phi_n\ny_{n+1} = 2*x_n*y_n + b + psi_n\n```\n\n");
    report.push_str(&format!("### Trace Summary\n- **Trace Length:** {} states\n- **Steps Executed:** {} iterations\n\n", snapshot.trace.len(), snapshot.trace.len() - 1));
    report.push_str(&format!("### Final State\n```\nx_final: {}\ny_final: {}\n```\n\n", field_to_hex(&snapshot.final_state.x), field_to_hex(&snapshot.final_state.y)));
    
    report.push_str("---\n\n");
    report.push_str("## Stage 07-09: Trace Commitment\n\n");
    report.push_str(&format!("### Final Trace Root\n```\n{}\n```\n\n", bytes_to_hex(&snapshot.trace_root)));
    
    report.push_str("---\n\n");
    report.push_str("## Stage 10-12: Claim and Public Inputs\n\n");
    report.push_str("### Storm Claim\n| Field | Value |\n|-------|-------|\n");
    report.push_str(&format!("| Side A Hash | `{}` |\n", bytes_to_hex(&snapshot.side_a_hash)));
    report.push_str(&format!("| Side B Hash | `{}` |\n", bytes_to_hex(&snapshot.side_b_hash)));
    report.push_str(&format!("| Context Hash | `{}` |\n", bytes_to_hex(&snapshot.context_hash)));
    report.push_str(&format!("| Trace Root | `{}` |\n\n", bytes_to_hex(&snapshot.trace_root)));
    
    report.push_str("---\n\n");
    report.push_str("## Stage 13-14: UDOT Derivation\n\n");
    report.push_str(&format!("**Seal Line:**\n```\n{}\n```\n\n", snapshot.seal_line));
    report.push_str(&format!("**Crest:**\n```\n{}\n```\n\n", snapshot.crest));
    report.push_str(&format!("**Matrix Form (8x8):**\n```\n{}\n```\n\n", snapshot.matrix_form));
    
    report.push_str("---\n\n**Result:** ✅ Pipeline walk successful\n");

    let reports_dir = Path::new("/Users/mcrae/Desktop/AURA/reports");
    if !reports_dir.exists() {
        let _ = fs::create_dir_all(reports_dir);
    }
    let report_path = reports_dir.join("AURA_MANUAL_PIPELINE_WALK_V1.md");
    fs::write(&report_path, report).expect("Failed to write report");
    println!("\n📄 Full report: reports/AURA_MANUAL_PIPELINE_WALK_V1.md");
}

// =============================================================================
// MAIN TEST
// =============================================================================

#[test]
fn manual_pipeline_walk_v1() {
    let args: Vec<String> = env::args().collect();
    let mode = ExecutionMode::from_args(&args);

    let context_bytes = make_test_context();
    let iteration_count: u64 = 4;

    match mode {
        ExecutionMode::Compact => {
            let snapshot = run_pipeline(
                "AURA_MANUAL_WALK_TEST_VECTOR_V1",
                TEST_SIDE_A, TEST_SIDE_B, context_bytes, iteration_count,
            );
            output_compact(&snapshot);
            generate_compact_markdown(&snapshot);
            println!("\n✅ Compact mode completed successfully!");
        }
        ExecutionMode::Full => {
            let snapshot = run_pipeline(
                "AURA_MANUAL_WALK_TEST_VECTOR_V1",
                TEST_SIDE_A, TEST_SIDE_B, context_bytes, iteration_count,
            );
            output_full(&snapshot);
            generate_full_markdown(&snapshot);
            println!("\n✅ Full mode completed successfully!");
        }
        ExecutionMode::Diff { fixture_a, fixture_b } => {
            let (side_a_a, side_b_a) = get_fixture(fixture_a);
            let (side_a_b, side_b_b) = get_fixture(fixture_b);

            let snap_a = run_pipeline(
                &format!("fixture_{}", fixture_a),
                side_a_a, side_b_a, context_bytes, iteration_count,
            );
            let snap_b = run_pipeline(
                &format!("fixture_{}", fixture_b),
                side_a_b, side_b_b, context_bytes, iteration_count,
            );
            output_diff(&snap_a, &snap_b);
            generate_diff_markdown(&snap_a, &snap_b);
            println!("\n✅ Diff mode completed successfully!");
        }
    }
}
