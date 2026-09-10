# Aura Runtime Usage Log

Purpose: compare verified work per allowance, not just wall-clock runtime.

## Historical baseline (supplied figures; not independently verified)

| Run | Runtime | Usage | Runtime architecture | Notes |
|---|---:|---:|---|---|
| Slice 3 | ~10 min | ~100% | pre-V2 | allowance exhausted rapidly |
| Slice 4 | ~12–13 min | ~82% | Q16 V2 | continuous execution improved |
| Slice 5 | ~20 min | ~95% | Q16 V3, pre-Codex-update, Fast | major 41-file API isolation |

## V4 Run 6

Variables:
- updated Codex;
- Q16 V4;
- strongest selected Astra model / Ultra reasoning;
- `service_tier = "default"` (Standard);
- Aura project agents disabled;
- repository-backed SLICE state.

Because several variables change, Run 6 becomes the new V4 baseline rather than a pure one-variable experiment.

| Time | Checkpoint | 5h used % | 5h remaining % | Repo state / evidence | Notes |
|---|---|---:|---:|---|---|
| | START | | | | |
| | after initial pickup / first tool batch | | | | |
| | first DONE DAG node | | | | |
| | first commit | | | | |
| | +5 min | | | | |
| | +10 min | | | | |
| | +15 min | | | | |
| | STOP | | | | |

## Primary metric

`verified DONE DAG nodes + integration closures / allowance used`

Secondary:
- wall-clock runtime;
- files meaningfully changed;
- targeted validations passed;
- number of global replans;
- number of compactions/resumes if visible.

Installation note: no START measurement recorded; project settings have not yet been observed after host reload.
