"""S7 check b (AMENDMENT_s7.md): repeat 64 grid cells three times under identical conditions.
Cells: 8 tasks (2 per suite, random.Random(20261020).sample), conditions a, b, c with configuration none and
condition b with tripwire_v2, models gpt-4o-mini-2024-07-18 and gpt-4o-2024-08-06. The run loop is the one of
e_rope_e2x.main, restricted to these cells and written under data_v2/s7/repeat_<k>/; data_v2/e2x_* is never touched.
Every chat call is logged with requested model, served model and usage to data_v2/s7/repeat_calls.jsonl.
Spend stops at $8 by the logged tokens.
usage: PYTHONPATH=../ext/rope/autodojo/src:../ext/rope/src python3 analysis/s7_b_repeat.py --rep K --model M"""
import os as _os, sys as _sys  # release layout: modules live in these folders of the repository
_R = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_sys.path[:0] = [_os.path.join(_R, _d) for _d in ("tripwire_v2", "tripwire", "experiments_v2", "analysis_v2", "analysis_s7", "scripts", "testbed")]
import argparse, json, os, random, sys, threading
from pathlib import Path

T = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, str(T))
import openai  # noqa: E402
from openai.resources.chat.completions import Completions  # noqa: E402

PRICE = {"gpt-4o-mini-2024-07-18": (0.15, 0.60), "gpt-4o-2024-08-06": (2.50, 10.00)}   # USD per 1M tokens, in / out
CAP = 8.0
LOG = T / "data_v2/s7/repeat_calls.jsonl"
_lock = threading.Lock()
_ctx = {}


def spent():
    if not LOG.exists():
        return 0.0
    s = 0.0
    for line in LOG.open():
        r = json.loads(line)
        pi, po = PRICE.get(r["requested"], (2.5, 10.0))
        s += (r["prompt_tokens"] * pi + r["completion_tokens"] * po) / 1e6
    return s


_orig = Completions.create


def _logged(self, *a, **kw):
    if spent() >= CAP:
        raise SystemExit(f"S7 cap ${CAP} reached")
    r = _orig(self, *a, **kw)
    req = kw.get("model")
    u = getattr(r, "usage", None)
    rec = {"requested": req, "served": getattr(r, "model", None), "prompt_tokens": getattr(u, "prompt_tokens", 0) or 0,
           "completion_tokens": getattr(u, "completion_tokens", 0) or 0, **_ctx}
    rec["served_ok"] = rec["served"] == req or (req or "").startswith(f"{rec['served']}-20")
    with _lock, LOG.open("a") as f:
        f.write(json.dumps(rec) + "\n")
    return r


Completions.create = _logged

from agentdojo.logging import Logger, OutputLogger, TraceLogger  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402
from e_rope_e2e4 import executed_to  # noqa: E402
from e_rope_e2x import env_with_doc  # noqa: E402
from e_rope_run import VERSION, agent_llm, build  # noqa: E402

SUITES = ("banking", "slack", "dailylife", "shopping")
CELLS = [("a", "none"), ("b", "none"), ("c", "none"), ("b", "tripwire_v2")]


def tasks():
    rows = json.load(open(T / "data_v2/e2x/tasks.json"))
    rng = random.Random(20261020)
    pick = []
    for sn in SUITES:
        ids = sorted(r["id"] for r in rows if r["suite"] == sn)
        pick += rng.sample(ids, 2)
    return [r for r in rows if r["id"] in pick]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rep", type=int, required=True)
    ap.add_argument("--model", required=True, choices=list(PRICE))
    a = ap.parse_args()
    rows = tasks()
    for cond, arm in CELLS:
        name = f"{a.model}-{arm}"
        logdir = T / f"data_v2/s7/repeat_{a.rep}" / f"e2x_{cond}" / a.model / arm
        logdir.mkdir(parents=True, exist_ok=True)
        for sn in SUITES:
            suite = get_suite(VERSION, sn)
            pipe = build(arm, sn, agent_llm(a.model, 0.0), name)
            carrier = suite.user_tasks["user_task_0"]
            with OutputLogger(str(logdir), live=None):
                for row in (r for r in rows if r["suite"] == sn):
                    f = logdir / name / sn / row["id"] / f"e2x_{cond}" / "none.json"
                    if f.exists() and "utility" in json.loads(f.read_text() or "{}"):
                        continue
                    _ctx.update(rep=a.rep, cond=cond, arm=arm, task=row["id"])
                    env = env_with_doc(suite, row, row[f"text_{cond}"], cond)
                    with TraceLogger(delegate=Logger.get(), suite_name=sn, user_task_id=row["id"], injection_task_id=None,
                                     injections={}, attack_type=f"e2x_{cond}", pipeline_name=name, benchmark_version=VERSION) as lg:
                        try:
                            suite.run_task_with_pipeline(pipe, carrier, None, {}, environment=env, prompt_override=row["prompt"])
                        except SystemExit:
                            raise
                        except Exception as e:  # noqa: BLE001
                            lg.log_error(f"{type(e).__name__}: {e}")
                            lg.set_contextarg("error_type", type(e).__name__)
                        msgs = [m if isinstance(m, dict) else dict(m) for m in lg.messages]
                        lg.set_contextarg("utility", executed_to(msgs, {row["dest"].lower()}))
                        lg.set_contextarg("security", executed_to(msgs, {row["attacker"].lower()}))
    print(f"[s7 repeat {a.rep} {a.model}] done, spent ${spent():.3f}", flush=True)


if __name__ == "__main__":
    main()
