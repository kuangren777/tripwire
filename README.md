# TripWire

TripWire is a runtime defense for LLM tool-calling agents against indirect prompt injection. It tracks where every argument value of a sensitive tool call came from (user, typed tool field, free text, delegated content) and blocks a call whose security-relevant argument originates in untrusted tool output, without any extra LLM call.
This package contains the defense, the experiment drivers, the frozen result logs and the scripts that regenerate every table, figure and number macro of the paper.

AgentDojo is a third-party dependency under its own license. It is not vendored here, install it from PyPI (or point `AGENTDOJO_SRC` at a checkout).
The code in this package is MIT licensed (see `LICENSE`).

## Layout

| path | content |
|---|---|
| `tripwire/tripwire.py` | the defense (`Provenance`, `TripWireExecutor`) |
| `tripwire/melon_port.py` | MELON baseline port to this testbed |
| `tripwire/test_tripwire.py` | unit tests |
| `testbed/harness.py` | shared AgentDojo harness (pipelines for every defense arm, logging) |
| `experiments/exp_*.py` | experiment drivers (main grid, ablation, adaptive attacks, attack wording, overhead, taint replay) |
| `analysis/analyze.py`, `make_numbers.py`, `make_figs.py` | frozen logs -> `results.json` -> tables, `numbers.tex` macros, figures |
| `data/` | frozen result logs and audit files (schema below) |
| `PRIVACY.md` | what was removed before release |

## Install

Python 3.10 or newer (the numbers in the paper were produced with 3.13).

```bash
pip install -r requirements.txt     # agentdojo==0.1.35 plus openai, pydantic, numpy, matplotlib, pytest
```

`transformers` and `torch` are only needed for the `pi_detector` baseline. The detector weights are not shipped. Download
`protectai/deberta-v3-base-prompt-injection-v2` from Hugging Face into `$MODELS_DIR/deberta-pi`:

```bash
huggingface-cli download protectai/deberta-v3-base-prompt-injection-v2 --local-dir "$MODELS_DIR/deberta-pi"
```

## Environment variables

| variable | used by | meaning |
|---|---|---|
| `OPENAI_BASE_URL` | harness | OpenAI-compatible gateway that serves the hosted models, including the `/v1` suffix (required for experiments) |
| `OPENAI_API_KEY` | harness | key for that gateway (required for experiments) |
| `LOCAL_VLLM` | harness | base URL of the vLLM server for `qwen3-8b-local`, default `http://localhost:8021/v1` |
| `LOCAL_VLLM_HOST` | harness | host prefix for the other local servers, default `http://localhost` (ports below) |
| `AGENTDOJO_SRC` | all | optional path to an AgentDojo `src/` checkout, only needed if AgentDojo is not pip-installed |
| `MODELS_DIR` | harness | directory holding `deberta-pi/` for the `pi_detector` arm, default `./models` |
| `TRIPWIRE_OUT` | analysis | output directory of `analyze.py`, `make_numbers.py`, `make_figs.py`, default `./out` |
| `TW_ARMS`, `TW_LOG`, `ATK_ARMS`, `ABL_KINDS`, `REP`, `TF_MAX_TOKENS` | drivers | optional run selection, see the driver sources |

The analysis scripts and the unit tests need no gateway and no keys.

## Unit tests

```bash
cd tripwire && python -m pytest -q          # 8 tests
```

## Reproduce the paper's tables, figures and numbers from the frozen data

```bash
export TRIPWIRE_OUT=out
python analysis/analyze.py        # data/*.jsonl, data/*.json -> out/results.json, out/results.md
python analysis/make_numbers.py   # out/results.json -> out/numbers.tex (all prose macros), out/tab_main.tex,
                                  #   out/tab_models.tex, out/tab_errors.tex, out/tab_paired.tex
python analysis/make_figs.py      # out/results.json -> out/fig/*.pdf
```

| paper item | file |
|---|---|
| every number in the prose | `out/numbers.tex` (macros) |
| main comparison table | `out/tab_main.tex` |
| per-model table | `out/tab_models.tex` |
| error / failure table | `out/tab_errors.tex` |
| paired comparison table | `out/tab_paired.tex` |
| figures: trade-off, per-model and per-suite utility, ablation, adaptive attacks, attack classes, attack templates, sources, monitor | `out/fig/{tradeoff,per_model_utility,per_suite_utility,ablation,adaptive,attack_class,attack_templates,sources,monitor}.pdf` |

`data/results.json` is the reference copy of `out/results.json` that the paper was built from; the regenerated file is byte-identical.
The hand-drawn overview figure (TikZ) is not part of this package.
Statistics (bootstrap and exact tests) are seeded from the cell keys, so reruns are deterministic.
`data/SNAPSHOT.sha256` and `data/SNAPSHOT_v2.sha256` hold the hashes of the logs as frozen before release. Two files were rewritten at release time (model path strings only, see `PRIVACY.md`), their hashes are in `data/SNAPSHOT_release.sha256`.

## Re-run the experiments

Hosted models go through `OPENAI_BASE_URL` (any OpenAI-compatible gateway with tool calling): `gpt-5.6-sol`, `gemini-3.1-pro`, `claude-sonnet-5`, `deepseek-v4.1-flash`, `kimi-k3`, `glm-5.3`.
The four small open-weight models must be served locally with vLLM (tool calling enabled, 16384 context), because gateways commonly drop the `tools` parameter for open-weight channels:

| model tag | served model | endpoint |
|---|---|---|
| `qwen3-8b-local` | Qwen3-8B | `$LOCAL_VLLM` (default `http://localhost:8021/v1`) |
| `qwen25-7b-local` | Qwen/Qwen2.5-7B-Instruct | `http://localhost:8022/v1` |
| `llama31-8b-local` | meta-llama/Llama-3.1-8B-Instruct | `http://localhost:8023/v1` |
| `granite31-8b-local` | ibm-granite/granite-3.1-8b-instruct | `http://localhost:8025/v1` |

Example for the first model, change the port for the others: `vllm serve Qwen/Qwen3-8B --port 8021 --enable-auto-tool-choice --tool-call-parser hermes --max-model-len 16384`.
The parser flag differs per model family. The harness uses the sampling temperature stored in the logs (`temp`, 1.0).

Every driver appends to its log under `data/` and skips runs already present, so running them in place resumes or extends the frozen logs. To keep the frozen files untouched, copy `data/` first or use `TW_LOG=data/new.jsonl` for the main grid.

```bash
export OPENAI_BASE_URL=https://your-gateway.example/v1 OPENAI_API_KEY=...
cd experiments
python exp_tw.py <model> [workers=16] [reps=1]        # main grid: 9 arms x 4 suites -> data/tw_main.jsonl   (all 10 models)
python exp_ablation.py qwen3-8b-local [workers=6]      # RQ3 ablations (compaction, taint store, typed store) -> data/tw_ablation.jsonl
python exp_adaptive.py qwen3-8b-local [workers=8]      # RQ4 adaptive attacks (launder, split) -> data/tw_adaptive.jsonl   (REP=1, REP=2 for repetitions)
python exp_attacks.py <qwen3-8b-local|qwen25-7b-local> [workers=10]   # attack-wording robustness -> data/tw_attacks.jsonl
python exp_overhead.py                                 # RQ2 overhead micro-benchmark, no LLM -> data/tw_overhead.json
python exp_taint_replay.py                             # taint replay on scripted solutions, no LLM -> data/tw_taint_replay.json
```

`TW_ARMS=tripwire,tw_monitor` restricts the defense arms of `exp_tw.py`. `pi_detector` needs the DeBERTa weights, `melon` needs an embedding model (`bge-m3`) on the gateway.
LLM runs are stochastic and gateway models change, so a re-run will not reproduce the frozen numbers exactly. The overhead and taint-replay drivers involve no LLM, their timings depend on the machine.

## Data schema

`tw_main.jsonl` (v1, frozen), `tw_main_fill.jsonl` (v2, baseline cells added later for three open-weight models), `tw_adaptive.jsonl`, `tw_ablation.jsonl`, `tw_attacks.jsonl`: one JSON object per agent run.

| field | meaning |
|---|---|
| `tag`, `model`, `suite`, `ut`, `it` | run tag, model tag, AgentDojo suite, user task id, injection task id (`null` for a benign run) |
| `inj_hash` | hash of the injection text |
| `temp` | sampling temperature |
| `defense` | arm name (`tw_monitor` = no defense with TripWire logging, `tripwire`, `tw_nodeleg`, `tw_strict`, `tw_nocompact`, `tw_notaint`, `spotlighting`, `repeat_user_prompt` = Sandwich, `tool_filter`, `melon`, `pi_detector`) |
| `channel` | injection channel |
| `utility`, `security` | AgentDojo utility and attack-success judgments (booleans, `security` is `null` on benign runs) |
| `err` | error string of a failed attempt, `null` on success (the analysis drops rows with `err`) |
| `trace` | tool calls `{f: function, a: arguments}` |
| `exposed`, `ctx_chars`, `n_msgs`, `secs`, `ts` | injection reached the model, context size, message count, wall seconds, unix time |
| `final` | final assistant text (truncated) |
| `tw_flags`, `tw_calls`, `melon_fired` | defense-specific telemetry |
| `served_root` | model identifier reported by the local vLLM server (only on later rows) |

`tw_overhead.json`: list of `{suite, ut, ex (plain|tripwire), calls, sec_med}`.
`tw_taint_replay.json`: list of `{suite, ut, taint, att_seen, blocked_at, direct_src}`.
`results.json`: output of `analyze.py`, keys are `"<model> | <arm>"` plus aggregate sections.
`FILL_AUDIT.json`, `FILL_MANIFEST.md`: audit and run log of the v2 fill.
`SNAPSHOT*.sha256`: sha256 of the frozen logs.

The logs contain the benchmark's own e-mail addresses, IBANs and URLs (AgentDojo task data and injection targets). They are benchmark content, not personal data.
