#!/usr/bin/env python3
from pathlib import Path
from datetime import datetime, timezone
import argparse

ap = argparse.ArgumentParser()
ap.add_argument("--repo", default=".")
ap.add_argument("--label", required=True)
ap.add_argument("--used", type=float)
ap.add_argument("--remaining", type=float)
ap.add_argument("--evidence", default="")
ap.add_argument("--notes", default="")
a = ap.parse_args()

if a.used is None and a.remaining is None:
    raise SystemExit("provide --used or --remaining")
used = a.used if a.used is not None else 100.0 - a.remaining
remaining = a.remaining if a.remaining is not None else 100.0 - a.used

p = Path(a.repo).resolve() / "aura-runtime" / "RUN_METRICS.md"
if not p.exists():
    raise SystemExit(f"missing {p}")

stamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
with p.open("a", encoding="utf-8") as f:
    f.write(f"\n| {stamp} | {a.label} | {used:.1f} | {remaining:.1f} | {a.evidence} | {a.notes} |")
print(f"Recorded {a.label}: used={used:.1f}% remaining={remaining:.1f}%")
