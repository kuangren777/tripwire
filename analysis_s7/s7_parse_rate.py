"""S7 pre-check: tool-call parse rate per model, with the definitions of EngageFuzz
AMENDMENT_s1a_toolparser.md and AMLP analysis/s3_parse_rate.py: tool-call rate = share of runs with at least one parsed
tool call, threshold >= 0.90; unparsed = share of runs whose final assistant text still holds a tool-call JSON object
(s1b_reparse.calls_in_text), threshold <= 0.02. Reads the recorded run logs only, no model call.
usage: python3 analysis/s7_parse_rate.py -> data_v2/s7/parse_rate.json"""
import os as _os, sys as _sys  # release layout: modules live in these folders of the repository
_R = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_sys.path[:0] = [_os.path.join(_R, _d) for _d in ("tripwire_v2", "tripwire", "experiments_v2", "analysis_v2", "analysis_s7", "scripts", "testbed")]
import glob, json, os, sys

T = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
from s1b_reparse import calls_in_text  # noqa: E402

RATE_MIN, UNPARSED_MAX = 0.90, 0.02
EXPS = {"dev (e1_rope)": "data_v2/e1_rope", "held-out (v2_heldout)": "data_v2/v2_heldout", "grid a": "data_v2/e2x_a", "grid a_h": "data_v2/e2x_a_h",
        "grid b": "data_v2/e2x_b", "grid c": "data_v2/e2x_c", "grid c_h": "data_v2/e2x_c_h", "grid masked": "data_v2/e2x_m",
        "grid struck": "data_v2/e2x_s", "grid masked clean": "data_v2/e2x_ma", "held-out ROPE fixed (r2c)": "data_v2/r2c"}


def final_text(msgs):
    for m in reversed(msgs):
        if m["role"] == "assistant":
            c = m.get("content")
            return "".join(b.get("content") or "" for b in c if isinstance(b, dict)) if isinstance(c, list) else (c or "")
    return ""


def main():
    out = {"thresholds": {"call_rate_min": RATE_MIN, "unparsed_rate_max": UNPARSED_MAX}, "rows": []}
    for exp, root in EXPS.items():
        for mdir in sorted(glob.glob(os.path.join(T, root, "*/"))):
            model = os.path.basename(mdir.rstrip("/"))
            n = called = unparsed = 0
            for f in glob.glob(os.path.join(mdir, "**", "*.json"), recursive=True):
                try:
                    d = json.load(open(f))
                except Exception:  # noqa: BLE001
                    continue
                if "messages" not in d or "utility" not in d:
                    continue
                n += 1
                called += any(m["role"] == "assistant" and m.get("tool_calls") for m in d["messages"])
                unparsed += bool(calls_in_text(final_text(d["messages"])))
            if not n:
                continue
            r = {"experiment": exp, "model": model, "runs": n, "with_call": called, "unparsed_text_call": unparsed,
                 "call_rate": round(called / n, 4), "unparsed_rate": round(unparsed / n, 4)}
            r["pass"] = r["call_rate"] >= RATE_MIN and r["unparsed_rate"] <= UNPARSED_MAX
            out["rows"].append(r)
            print(f"{exp:28s} {model:32s} runs {n:6d} call {r['call_rate']:.3f} unparsed {r['unparsed_rate']:.3f} {'PASS' if r['pass'] else 'FAIL'}")
    os.makedirs(os.path.join(T, "data_v2/s7"), exist_ok=True)
    json.dump(out, open(os.path.join(T, "data_v2/s7/parse_rate.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
