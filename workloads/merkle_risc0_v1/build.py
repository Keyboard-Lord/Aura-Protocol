#!/usr/bin/env python3
"""Reproduce the exact adopted C3 source. No latest-version lookup or upgrade.

RUSTUP_HOME/CARGO_HOME may point at isolated installed host tooling. --guest-rust
must name the unpacked, hash-pinned official guest toolchain. Build --locked.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import urllib.request

HERE = Path(__file__).resolve().parent
LOCK = json.loads((HERE / "source-lock.json").read_text())
PIN = "3bbcd44d6459b9ef6ac0df3846dc9215514934e8"

def sha(p):
    with p.open("rb") as f:
        h = hashlib.sha256()
        for b in iter(lambda: f.read(1024*1024), b""): h.update(b)
    return h.hexdigest()

def fetch(url, dest, digest):
    if not dest.exists():
        tmp = dest.with_suffix(".partial")
        urllib.request.urlretrieve(url, tmp)
        if sha(tmp) != digest: raise RuntimeError("download hash mismatch: " + url)
        tmp.replace(dest)
    if sha(dest) != digest: raise RuntimeError("cached hash mismatch: " + str(dest))

def sources(download=False):
    assert LOCK["revision"] == PIN
    vendor = HERE / "vendor/risc0"
    if download and not vendor.exists():
        cache = HERE / "cache"; cache.mkdir(exist_ok=True)
        archive = cache / (PIN + ".tar.gz")
        fetch(LOCK["archive_url"], archive, LOCK["archive_sha256"])
        with tarfile.open(archive) as t:
            # Only the pinned regular files are materialized; no links/executable hooks.
            for m in t.getmembers():
                if not m.isfile(): continue
                name = m.name.split("/", 1)[1]
                if name not in LOCK["files"]: raise RuntimeError("unexpected source path")
                p = vendor / name; p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(t.extractfile(m).read()); p.chmod(m.mode & 0o777)
        for f in LOCK["lfs"]:
            p = vendor / f["file"]
            # The archive contains the exact LFS pointer; replace with its pinned object.
            if sha(p) != f["sha256"]: p.unlink()
            fetch(f["url"], p, f["sha256"])
    for name, digest in LOCK["files"].items():
        if sha(vendor / name) != digest: raise RuntimeError("source drift: " + name)
    print("source pin verified:", PIN, len(LOCK["files"]), "files", flush=True)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("action", choices=["fetch", "check", "guest", "prover", "verifier", "cpu"])
    p.add_argument("--guest-rust", type=Path)
    p.add_argument("--cargo", default="cargo")
    a = p.parse_args(); sources(a.action == "fetch")
    if a.action in ("fetch", "check"): return
    env = os.environ.copy()
    for key in ("RISC0_DEV_MODE", "RISC0_PROVER", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"):
        env.pop(key, None)
    base = [a.cargo, "+1.97.0"]
    if a.action == "guest":
        if not a.guest_rust: p.error("--guest-rust required")
        rustc = a.guest_rust / "bin/rustc"
        if sha(rustc) != LOCK["guest_toolchain"]["rustc_sha256"]: raise RuntimeError("guest compiler drift")
        env["RUSTC"] = str(rustc)
        # Verbatim flags from the approved pin's risc0-build for a user guest.
        env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(["-C", "passes=lower-atomic", "-C", "link-arg=-Ttext=0x00200800", "-C", "link-arg=--fatal-warnings", "-C", "panic=abort", "--cfg", 'getrandom_backend="custom"'])
        cmd = base + ["build", "--release", "--locked", "--manifest-path", str(HERE/"guest/Cargo.toml"), "--target", "riscv32im-risc0-zkvm-elf"]
    else:
        cmd = base + ["rustc" if a.action == "cpu" else "build", "--release", "--locked", "--manifest-path", str(HERE/"Cargo.toml")]
        if a.action != "verifier": cmd += ["--features", "prove"]
        if a.action == "cpu": cmd += ["--target", "x86_64-apple-darwin", "--", "-l", "framework=Metal", "-l", "framework=Foundation"]
    subprocess.run(cmd, env=env, check=True)

if __name__ == "__main__": main()
