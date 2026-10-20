"""Read-only check of the local Qwen3-8B batch: per launch phase, runs, share with a
parsed tool call, share whose final text still holds a tool-call JSON object (s1b_reparse.calls_in_text), tool calls
whose arguments carry tool-schema text ('"type": "object"' or 'Input schema for'), and runs longer than 300 s
(AgentDojo 'duration', whole run). Thresholds: call share >= 90%, unparsed <= 2%. No model call, no data change.
usage: python3 analysis/s7_cfff_check.py -> data_v2/s7/vllm_batch_check.json"""
import os as _os, sys as _sys  # release layout: modules live in these folders of the repository
_R = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_sys.path[:0] = [_os.path.join(_R, _d) for _d in ("tripwire_v2", "tripwire", "experiments_v2", "analysis_v2", "analysis_s7", "scripts", "testbed")]
import datetime, glob, json, os, sys

T = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
from s1b_reparse import calls_in_text  # noqa: E402

SCHEMA = ('"type": "object"', "Input schema for")
# launch phases in SGT from e1_qwen*.sh and AF_PM.md (container clock is PDT, +15 h)
PHASES = [("main launch, 4 arm processes", None, datetime.datetime(2026, 10, 8, 2, 0), "24 in flight"),
          ("main + helpers", datetime.datetime(2026, 10, 8, 2, 0), datetime.datetime(2026, 10, 8, 4, 22), "about 48 in flight"),
          ("resume after 8021 outage, main processes", datetime.datetime(2026, 10, 8, 4, 22), None, "24 in flight")]


def text(c):
    return "".join(b.get("content") or "" for b in c if isinstance(b, dict)) if isinstance(c, list) else (c or "")


def main():
    rows = {p[0]: dict(runs=0, called=0, unparsed=0, schema_calls=0, calls=0, over300=0, conc=p[3]) for p in PHASES}
    for f in glob.glob(os.path.join(T, "data_v2/e1_rope/qwen3-8b-local/**/*.json"), recursive=True):
        try:
            d = json.load(open(f))
        except Exception:  # noqa: BLE001
            continue
        if "messages" not in d or "utility" not in d:
            continue
        t = datetime.datetime.strptime(d["evaluation_timestamp"][:19], "%Y-%m-%d %H:%M:%S") + datetime.timedelta(hours=15)
        ph = next(p[0] for p in PHASES if (p[1] is None or t >= p[1]) and (p[2] is None or t < p[2]))
        R = rows[ph]
        R["runs"] += 1
        tcs = [tc for m in d["messages"] if m["role"] == "assistant" for tc in (m.get("tool_calls") or [])]
        R["called"] += bool(tcs)
        R["calls"] += len(tcs)
        R["schema_calls"] += sum(any(s in json.dumps(tc.get("args") or {}) for s in SCHEMA) for tc in tcs)
        final = next((text(m.get("content")) for m in reversed(d["messages"]) if m["role"] == "assistant"), "")
        R["unparsed"] += bool(calls_in_text(final))
        R["over300"] += (d.get("duration") or 0) > 300
    out = []
    for name, R in rows.items():
        R.update(batch=name, host="local GPU server (shared vLLM port 8021)", call_rate=round(R["called"] / R["runs"], 4) if R["runs"] else None,
                 unparsed_rate=round(R["unparsed"] / R["runs"], 4) if R["runs"] else None)
        R["pass"] = bool(R["runs"]) and R["call_rate"] >= 0.90 and R["unparsed_rate"] <= 0.02
        out.append(R)
        print(R)
    json.dump(out, open(os.path.join(T, "data_v2/s7/vllm_batch_check.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
