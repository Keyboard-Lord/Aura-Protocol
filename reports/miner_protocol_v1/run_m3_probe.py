#!/usr/bin/env python3
"""Bounded local measurements, not a miner network or protocol authority."""
import argparse
import datetime
import json
import math
import pathlib
import platform
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]


def command(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=64)
    parser.add_argument("--output", type=pathlib.Path, default=ROOT / "reports/miner_protocol_v1/m3_measurements.json")
    args = parser.parse_args()
    if not 2 <= args.trials <= 512:
        parser.error("--trials must be 2..512")
    binary = ROOT / "target/release/examples/miner_m3_probe"
    environment = {
        "captured_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "platform": platform.platform(), "machine": platform.machine(),
        "rustc": command("rustc", "-Vv"), "build": "cargo build -p aura_sdk_v1 --offline --release --example miner_m3_probe",
        "threads_per_sample": 1, "N_values": [8, 16, 32, 64, 128],
        "peak_memory_method": "Fresh Python monitor per N; its only child is the Rust probe. getrusage(RUSAGE_CHILDREN).ru_maxrss, Darwin bytes / Linux KiB converted to bytes, including warmup and diagnostics.",
    }
    if platform.system() == "Darwin":
        cpu = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], text=True, capture_output=True)
        environment["cpu"] = cpu.stdout.strip() if cpu.returncode == 0 else "unavailable: " + cpu.stderr.strip()
    results = []
    # A fresh monitor avoids a cumulative high-water mark across different N runs.
    monitor = """
import json, platform, resource, subprocess, sys
run = subprocess.run(sys.argv[1:], text=True, capture_output=True, check=True, timeout=60)
sample = json.loads(run.stdout)
rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
sample['process_peak_rss_bytes'] = rss * (1 if platform.system() == 'Darwin' else 1024)
print(json.dumps(sample))
"""
    for n in environment["N_values"]:
        invocation = [str(binary), str(n), str(args.trials)]
        run = subprocess.run([sys.executable, "-c", monitor, *invocation], cwd=ROOT, text=True, capture_output=True, check=True, timeout=65)
        sample = json.loads(run.stdout)
        if sample["debug_assertions"]:
            raise RuntimeError("measure release executable only")
        hashes = [int(h, 16) for h in sample["proof_hashes_hex"]]
        assert len(set(hashes)) == len(hashes), "unexpected duplicate proof hashes"
        for bits, key in [(255, "q_1_2"), (254, "q_1_4"), (252, "q_1_16")]:
            assert sum(h <= (1 << bits) - 1 for h in hashes) == sample["diagnostic_hits"][key]
        assert sample["nonce_propagation"]["trace_root_changed"]
        assert sample["nonce_propagation"]["proof_changed"]
        results.append(sample)
        print(f"N={n}: {sample['mean_trial_ms']} ms/trial; {sample['trials_per_second']} trials/s; {sample['qualifying_hashes_observed']}/{args.trials} hits", flush=True)
    total = sum(s["trials"] for s in results)
    thresholds = []
    for bits, key in [(255, "q_1_2"), (254, "q_1_4"), (252, "q_1_16")]:
        target = (1 << bits) - 1
        q = (target + 1) / 2**256
        hits = sum(s["diagnostic_hits"][key] for s in results)
        thresholds.append({"target_hex": f"{target:064x}", "q": q, "trials": total, "hits": hits,
                           "observed_rate": hits / total, "expected_hits": total * q,
                           "binomial_reference_sd_hits": math.sqrt(total * q * (1-q))})
    assert thresholds[0]["hits"] > thresholds[1]["hits"] > thresholds[2]["hits"] > 0
    output = {"classification": "M3 NON-AUTHORITATIVE IMPLEMENTATION EVIDENCE", "environment": environment,
              "samples": results, "diagnostic_thresholds": thresholds,
              "limits": "Deterministic bounded sample, not a randomness/hardness proof. Different N uses different signed J. Threshold diagnostics reuse the same completed hashes per job; only its signed target qualifies."}
    args.output.write_text(json.dumps(output, indent=2) + "\n")


if __name__ == "__main__":
    main()
