# tw_main_fill.jsonl (data v2) — baseline cells missing from frozen tw_main.jsonl (v1)

Arms: tool_filter, pi_detector, melon. Models: qwen25-7b-local, llama31-8b-local, granite31-8b-local. Target 291 rows per cell.
Every row from the second Llama start onward carries served_root (the first 126 Llama tool_filter rows predate the field; root verified at start = meta-llama/Llama-3.1-8B-Instruct).

| time (SGT) | event |
|---|---|
| 2026-10-06 ~02:25 | Llama fill start (8023 shared, workers 8) |
| 2026-10-06 02:35 | Llama restarted to add served_root (old PID 1850778 killed mid-run; check partial lines before freeze) |
| 2026-10-06 02:41 | Qwen2.5 vLLM on a lab GPU server, GPU5, PID 3687229, mem 0.45, otherwise identical to serve_qwen25_7b.sh; fill PID 1927964 |
| 2026-10-06 03:02 | Llama restarted (stale sockets suspected), PID 2196332 |
| 2026-10-06 03:22 | Llama restarted with TF_MAX_TOKENS=1024 (PID 2306724): tool-filter selection reply capped; greedy Llama repeated tool names to the 16k limit, each call timed out (600 s x3) and fell back to all tools. Rows before 03:22 finished in seconds, so the cap would not have changed them. Qwen2.5 tool_filter ran uncapped. |
| 2026-10-06 04:30 | Qwen2.5 + Llama fill done; context-overflow failures retried twice, 1 run per model still overflows (missing, same policy as v1). Qwen2.5 vLLM PID 3687229 stopped by PID. |
| 2026-10-06 04:30 | Granite vLLM on GPU5, PID 3700133, mem 0.45, otherwise identical to serve_granite.sh; fill PID 2768387, TF_MAX_TOKENS=1024 |
