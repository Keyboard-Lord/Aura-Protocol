//! Local development harness. Not a worker endpoint or an adapter registration.
use anyhow::{ensure, Result};
use aura_c3_merkle_host::*;
use aura_compute_merkle_v1::*;
use risc0_zkvm::compute_image_id;
use std::{fs, time::Instant};

fn read_bound(path: &str, max: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let f = fs::File::open(path)?;
    ensure!(f.metadata()?.is_file(), "regular artifact required");
    let mut bytes = Vec::new();
    f.take(max as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= max, "artifact limit");
    Ok(bytes)
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let a: Vec<String> = std::env::args().collect();
    ensure!(
        a.len() == 6,
        "inspect|prove|verify guest.elf job-commitment-hex input.bin output.bin"
    );
    check_verifier_pin()?;
    ensure!(
        std::env::var_os("RISC0_DEV_MODE").is_none(),
        "dev mode forbidden"
    );
    let user = read_bound(&a[2], 8 * 1024 * 1024)?;
    let kernel = include_bytes!("../../vendor/risc0/risc0/zkos/v1compat/elfs/v1compat.elf");
    let binary = risc0_binfmt::ProgramBinary::new(&user, kernel).encode();
    let image = compute_image_id(&binary)?;
    let job: Hash = hex::decode(&a[3])?
        .try_into()
        .map_err(|_| anyhow::anyhow!("job digest length"))?;
    let input = read_bound(&a[4], MAX_INPUT_LEN)?;
    let batch = Batch::parse(&input).map_err(anyhow::Error::msg)?;
    batch.verify(sha256).map_err(anyhow::Error::msg)?;
    let journal = batch.journal(job, sha256);
    if a[1] == "inspect" {
        println!(
            "{}",
            serde_json::json!({"revision":REVISION,"guest_elf_sha256":hex::encode(sha256(&user)),"kernel_sha256":hex::encode(sha256(kernel)),"program_sha256":hex::encode(sha256(&binary)),"program_bytes":binary.len(),"image_id":image.to_string(),"journal_hex":hex::encode(journal),"control_root":CONTROL_ROOT,"verifier_parameters":VERIFIER_PARAMETERS,"classification":"candidate build identity; not proof evidence"})
        );
        return Ok(());
    }
    let start = Instant::now();
    let output = if a[1] == "prove" {
        #[cfg(not(feature = "prove"))]
        {
            anyhow::bail!("verifier-only binary");
        }
        #[cfg(feature = "prove")]
        {
            use risc0_zkvm::{get_prover_server, ExecutorEnv, ProverOpts};
            let mut stdin = job.to_vec();
            stdin.extend_from_slice(&(input.len() as u32).to_le_bytes());
            stdin.extend_from_slice(&input);
            let env = ExecutorEnv::builder()
                .write_slice(&stdin)
                .segment_limit_po2(16)
                .session_limit(Some(1 << 24))
                .build()?;
            let opts = ProverOpts::succinct();
            let receipt = get_prover_server(&opts)?.prove(env, &binary)?.receipt;
            let b = encode_output(&receipt, &journal, image)?;
            b
        }
    } else {
        ensure!(a[1] == "verify", "unknown operation");
        read_bound(&a[5], MAX_OUTPUT_LEN)?
    };
    let elapsed = start.elapsed().as_secs_f64();
    let verify = Instant::now();
    let receipt = verify_output(&output, &journal, image)?;
    if a[1] == "prove" {
        fs::write(&a[5], &output)?;
    }
    println!(
        "{}",
        serde_json::json!({"revision":REVISION,"mode":a[1],"image_id":image.to_string(),"journal_hex":hex::encode(journal),"output_bytes":output.len(),"seal_bytes":receipt.seal_size(),"operation_seconds":elapsed,"independent_verify_seconds":verify.elapsed().as_secs_f64(),"verified":true,"batch_count":batch.count(),"tree_depth":batch.depth(),"backend":"requires independent runtime telemetry; not inferred from proof success"})
    );
    Ok(())
}
