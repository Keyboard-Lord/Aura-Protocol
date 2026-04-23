//! Canonical storm execution runtime for the nonlinear lower layer.

use core::fmt;

use crate::{
    aura_hash521_v1, validate_context_bytes_v1, FieldElement521V1, StormContextErrorV1,
    StormState521V1, STORM_CONTEXT_V1_LEN,
};

pub const STORM_SIDE_INPUT_LEN_V1: usize = 110;
pub const AURA_X0_V1_DOMAIN_SEPARATOR: &[u8] = b"AURA_X0_V1";
pub const AURA_Y0_V1_DOMAIN_SEPARATOR: &[u8] = b"AURA_Y0_V1";
pub const AURA_C_A_V1_DOMAIN_SEPARATOR: &[u8] = b"AURA_C_A_V1";
pub const AURA_C_B_V1_DOMAIN_SEPARATOR: &[u8] = b"AURA_C_B_V1";
pub const AURA_STORM_X_V1_DOMAIN_SEPARATOR: &[u8] = b"AURA_STORM_X_V1";
pub const AURA_STORM_Y_V1_DOMAIN_SEPARATOR: &[u8] = b"AURA_STORM_Y_V1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StormExecutionInputsV1 {
    pub side_a: [u8; STORM_SIDE_INPUT_LEN_V1],
    pub side_b: [u8; STORM_SIDE_INPUT_LEN_V1],
    pub context_bytes_v1: [u8; STORM_CONTEXT_V1_LEN],
    pub iteration_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StormExecutionResultV1 {
    pub initial_state: StormState521V1,
    pub final_state: StormState521V1,
    pub a: FieldElement521V1,
    pub b: FieldElement521V1,
    pub trace: Vec<StormState521V1>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StormExecutionErrorV1 {
    IterationCountTooLarge { actual: u64 },
    InvalidContext(StormContextErrorV1),
}

impl fmt::Display for StormExecutionErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IterationCountTooLarge { actual } => {
                write!(f, "storm iteration count too large: {actual}")
            }
            Self::InvalidContext(error) => write!(f, "invalid storm context: {error}"),
        }
    }
}

impl std::error::Error for StormExecutionErrorV1 {}

impl StormExecutionInputsV1 {
    pub fn validate(&self) -> Result<(), StormExecutionErrorV1> {
        let iteration_count =
            usize::try_from(self.iteration_count).map_err(|_| StormExecutionErrorV1::IterationCountTooLarge {
                actual: self.iteration_count,
            })?;
        let _ = iteration_count.checked_add(1).ok_or(
            StormExecutionErrorV1::IterationCountTooLarge {
                actual: self.iteration_count,
            },
        )?;
        validate_context_bytes_v1(&self.context_bytes_v1)
            .map_err(StormExecutionErrorV1::InvalidContext)?;
        Ok(())
    }
}

pub fn derive_x0(side_a: &[u8; STORM_SIDE_INPUT_LEN_V1]) -> FieldElement521V1 {
    hash_domain_and_fixed_payload(AURA_X0_V1_DOMAIN_SEPARATOR, &[side_a.as_slice()])
}

pub fn derive_y0(side_b: &[u8; STORM_SIDE_INPUT_LEN_V1]) -> FieldElement521V1 {
    hash_domain_and_fixed_payload(AURA_Y0_V1_DOMAIN_SEPARATOR, &[side_b.as_slice()])
}

pub fn derive_a(context_bytes: &[u8; STORM_CONTEXT_V1_LEN]) -> FieldElement521V1 {
    hash_domain_and_fixed_payload(AURA_C_A_V1_DOMAIN_SEPARATOR, &[context_bytes.as_slice()])
}

pub fn derive_b(context_bytes: &[u8; STORM_CONTEXT_V1_LEN]) -> FieldElement521V1 {
    hash_domain_and_fixed_payload(AURA_C_B_V1_DOMAIN_SEPARATOR, &[context_bytes.as_slice()])
}

pub fn encode_step_u64_le(n: u64) -> [u8; 8] {
    n.to_le_bytes()
}

pub fn derive_phi_n(
    side_a: &[u8; STORM_SIDE_INPUT_LEN_V1],
    side_b: &[u8; STORM_SIDE_INPUT_LEN_V1],
    context_bytes: &[u8; STORM_CONTEXT_V1_LEN],
    n: u64,
) -> FieldElement521V1 {
    let step_bytes = encode_step_u64_le(n);
    hash_domain_and_fixed_payload(
        AURA_STORM_X_V1_DOMAIN_SEPARATOR,
        &[
            side_a.as_slice(),
            side_b.as_slice(),
            context_bytes.as_slice(),
            &step_bytes,
        ],
    )
}

pub fn derive_psi_n(
    side_a: &[u8; STORM_SIDE_INPUT_LEN_V1],
    side_b: &[u8; STORM_SIDE_INPUT_LEN_V1],
    context_bytes: &[u8; STORM_CONTEXT_V1_LEN],
    n: u64,
) -> FieldElement521V1 {
    let step_bytes = encode_step_u64_le(n);
    hash_domain_and_fixed_payload(
        AURA_STORM_Y_V1_DOMAIN_SEPARATOR,
        &[
            side_a.as_slice(),
            side_b.as_slice(),
            context_bytes.as_slice(),
            &step_bytes,
        ],
    )
}

pub fn storm_step(
    state: &StormState521V1,
    a: &FieldElement521V1,
    b: &FieldElement521V1,
    phi_n: &FieldElement521V1,
    psi_n: &FieldElement521V1,
) -> StormState521V1 {
    let x_squared = state.x.square_mod();
    let y_squared = state.y.square_mod();
    let xy = state.x.mul_mod(&state.y);
    let two_xy = xy.add_mod(&xy);

    StormState521V1 {
        x: x_squared.sub_mod(&y_squared).add_mod(a).add_mod(phi_n),
        y: two_xy.add_mod(b).add_mod(psi_n),
    }
}

pub fn build_storm_trace(inputs: &StormExecutionInputsV1) -> Vec<StormState521V1> {
    inputs
        .validate()
        .expect("storm execution inputs must be canonical before trace construction");

    let a = derive_a(&inputs.context_bytes_v1);
    let b = derive_b(&inputs.context_bytes_v1);
    let initial_state = StormState521V1 {
        x: derive_x0(&inputs.side_a),
        y: derive_y0(&inputs.side_b),
    };

    let trace_capacity = usize::try_from(inputs.iteration_count)
        .expect("validated storm iteration count must fit usize")
        .checked_add(1)
        .expect("validated storm iteration count must not overflow");
    let mut trace = Vec::with_capacity(trace_capacity);
    let mut state = initial_state;
    trace.push(state);

    for step in 0..inputs.iteration_count {
        let phi_n = derive_phi_n(&inputs.side_a, &inputs.side_b, &inputs.context_bytes_v1, step);
        let psi_n = derive_psi_n(&inputs.side_a, &inputs.side_b, &inputs.context_bytes_v1, step);
        state = storm_step(&state, &a, &b, &phi_n, &psi_n);
        trace.push(state);
    }

    trace
}

pub fn execute_storm_v1(inputs: &StormExecutionInputsV1) -> StormExecutionResultV1 {
    let trace = build_storm_trace(inputs);
    let initial_state = trace[0];
    let final_state = *trace
        .last()
        .expect("storm traces must contain at least the initial state");

    StormExecutionResultV1 {
        initial_state,
        final_state,
        a: derive_a(&inputs.context_bytes_v1),
        b: derive_b(&inputs.context_bytes_v1),
        trace,
    }
}

fn hash_domain_and_fixed_payload(domain_separator: &[u8], parts: &[&[u8]]) -> FieldElement521V1 {
    let mut msg_len = domain_separator.len();
    for part in parts {
        msg_len += part.len();
    }

    let mut msg = Vec::with_capacity(msg_len);
    msg.extend_from_slice(domain_separator);
    for part in parts {
        msg.extend_from_slice(part);
    }
    aura_hash521_v1(&msg)
}

#[cfg(test)]
mod tests {
    use crate::{execution_domain_v1, StormContextV1, STORM_CONTEXT_V1_VERSION};

    use super::{
        build_storm_trace, derive_a, derive_b, derive_phi_n, derive_psi_n, derive_x0, derive_y0,
        encode_step_u64_le, execute_storm_v1, StormExecutionInputsV1,
    };

    fn sample_inputs(iteration_count: u64) -> StormExecutionInputsV1 {
        let context = StormContextV1 {
            context_version: STORM_CONTEXT_V1_VERSION,
            network_id: [0x10; 32],
            intent_hash: [0x20; 32],
            freshness_nonce: [0x30; 32],
            valid_from: 100,
            valid_until: 200,
            controller_id: [0x40; 32],
            route_tag: [0x50; 32],
        };
        let context_bytes_v1 = context.to_bytes();
        assert_eq!(&context_bytes_v1[33..65], execution_domain_v1().as_slice());

        StormExecutionInputsV1 {
            side_a: [0xa5; 110],
            side_b: [0x5a; 110],
            context_bytes_v1,
            iteration_count,
        }
    }

    #[test]
    fn step_encoding_is_little_endian() {
        assert_eq!(encode_step_u64_le(0x0102_0304_0506_0708), [8, 7, 6, 5, 4, 3, 2, 1]);
    }

    #[test]
    fn storm_derivations_are_deterministic() {
        let inputs = sample_inputs(3);

        assert_eq!(derive_x0(&inputs.side_a), derive_x0(&inputs.side_a));
        assert_eq!(derive_y0(&inputs.side_b), derive_y0(&inputs.side_b));
        assert_eq!(derive_a(&inputs.context_bytes_v1), derive_a(&inputs.context_bytes_v1));
        assert_eq!(derive_b(&inputs.context_bytes_v1), derive_b(&inputs.context_bytes_v1));
        assert_eq!(
            derive_phi_n(&inputs.side_a, &inputs.side_b, &inputs.context_bytes_v1, 2),
            derive_phi_n(&inputs.side_a, &inputs.side_b, &inputs.context_bytes_v1, 2)
        );
        assert_eq!(
            derive_psi_n(&inputs.side_a, &inputs.side_b, &inputs.context_bytes_v1, 2),
            derive_psi_n(&inputs.side_a, &inputs.side_b, &inputs.context_bytes_v1, 2)
        );
    }

    #[test]
    fn storm_trace_has_initial_state_plus_iteration_count_steps() {
        let inputs = sample_inputs(5);
        let trace = build_storm_trace(&inputs);

        assert_eq!(trace.len(), 6);
        assert_eq!(trace[0].x, derive_x0(&inputs.side_a));
        assert_eq!(trace[0].y, derive_y0(&inputs.side_b));
    }

    #[test]
    fn execute_storm_returns_boundary_states_and_trace() {
        let inputs = sample_inputs(2);
        let result = execute_storm_v1(&inputs);

        assert_eq!(result.initial_state, result.trace[0]);
        assert_eq!(result.final_state, *result.trace.last().unwrap());
    }
}
