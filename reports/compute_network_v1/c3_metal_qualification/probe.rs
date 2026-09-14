use anyhow::{Result,ensure};
use risc0_zkvm::{compute_image_id,ExecutorEnv,ProverOpts,get_prover_server,Receipt,InnerReceipt};
use std::{fs,time::Instant};
fn main()->Result<()> {
 tracing_subscriber::fmt().with_writer(std::io::stderr).with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
 let a:Vec<String>=std::env::args().collect();ensure!(a.len()==4,"prove|verify ELF receipt.bin");
 let user_elf=fs::read(&a[2])?;
 let kernel=include_bytes!("@UPSTREAM@/risc0/zkos/v1compat/elfs/v1compat.elf");
 let elf=risc0_binfmt::ProgramBinary::new(&user_elf,kernel).encode();
 let id=compute_image_id(&elf)?;
 let t=Instant::now();
 let receipt:Receipt=if a[1]=="prove" {
  let opts=ProverOpts::succinct();let prover=get_prover_server(&opts)?;
  let env=ExecutorEnv::builder().segment_limit_po2(16).session_limit(Some(1<<20)).build()?;
  let receipt=prover.prove(env,&elf)?.receipt;
  ensure!(matches!(receipt.inner,InnerReceipt::Succinct(_)),"expected real succinct receipt");
  fs::write(&a[3],bincode::serialize(&receipt)?)?;receipt
 } else {
  ensure!(a[1]=="verify" || a[1]=="verify-negative","unknown mode");
  let b=fs::read(&a[3])?;ensure!(b.len()<8*1024*1024,"qualification artifact too large");
  bincode::deserialize(&b)?
 };
 let elapsed=t.elapsed().as_secs_f64();let v=Instant::now();receipt.verify(id)?;let verify=v.elapsed().as_secs_f64();
 ensure!(matches!(receipt.inner,InnerReceipt::Succinct(_)),"fake or unexpected receipt type");
 if a[1]=="verify-negative" {
  let mut cases=Vec::new();
  let mut reject=|name:&str,r:Receipt|->Result<()> {
   let outcome=std::panic::catch_unwind(|| r.verify(id));
   ensure!(matches!(outcome,Ok(Err(_))),"mutation not cleanly rejected: {name}");
   cases.push(name.to_owned());Ok(())
  };
  let mut r=receipt.clone();r.journal.bytes.push(1);reject("journal",r)?;
  let mut r=receipt.clone();if let InnerReceipt::Succinct(ref mut p)=r.inner {p.seal[0]^=1;}reject("seal",r)?;
  let mut r=receipt.clone();if let InnerReceipt::Succinct(ref mut p)=r.inner {p.seal.clear();}reject("empty_seal",r)?;
  let mut r=receipt.clone();if let InnerReceipt::Succinct(ref mut p)=r.inner {p.control_id=risc0_zkvm::sha::Digest::ZERO;}reject("control_id",r)?;
  let mut r=receipt.clone();r.metadata.verifier_parameters=risc0_zkvm::sha::Digest::ZERO;reject("metadata_parameters",r)?;
  let mut r=receipt.clone();if let InnerReceipt::Succinct(ref mut p)=r.inner {p.verifier_parameters=risc0_zkvm::sha::Digest::ZERO;}reject("inner_parameters",r)?;
  let fake=risc0_zkvm::FakeReceipt::new(receipt.claim()?);
  reject("fake_receipt",Receipt::new(InnerReceipt::Fake(fake),receipt.journal.bytes.clone()))?;
  ensure!(receipt.verify(risc0_zkvm::sha::Digest::ZERO).is_err(),"wrong image accepted");
  cases.push("image_id".into());
  eprintln!("AURA_NEGATIVE_RESULTS {}",serde_json::to_string(&cases)?);
 }
 let inner=receipt.inner.succinct()?;
 println!("{}",serde_json::json!({"mode":a[1],"image_id":id.to_string(),"type":"Succinct","elapsed_seconds":elapsed,"verify_seconds":verify,"seal_bytes":receipt.seal_size(),"artifact_bytes":fs::metadata(&a[3])?.len(),"journal_hex":hex::encode(&receipt.journal.bytes),"control_id":inner.control_id.to_string(),"verifier_parameters":inner.verifier_parameters.to_string(),"verified":true,"classification":"isolated upstream qualification only; not Aura canonical bytes"}));
 Ok(())
}
