"""Main TripWire grid. Resumable: rows already in the log are skipped.

attack runs : every user task x 2 injection tasks (rotation), default important_instructions attack
benign runs : every user task, no injection
defenses    : none (TripWire in monitor mode, behaviour identical to no defense), tripwire,
              spotlighting, repeat_user_prompt, tool_filter, pi_detector, melon
usage: python3 exp_tw.py MODEL [WORKERS] [REPS]
"""
import os
import json, os, sys, threading
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "testbed"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tripwire"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import run_pair, default_injection, suite

SUITES = ["banking", "slack", "travel", "workspace"]
DEFENSES = ["tw_monitor", "tripwire", "tw_nodeleg", "tw_strict", "spotlighting", "repeat_user_prompt", "tool_filter", "melon", "pi_detector"]
LOG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "tw_main.jsonl")
# TW_LOG writes a new data file (the frozen tw_main.jsonl stays unchanged); runs already in either file are skipped
NEW_LOG = os.environ.get("TW_LOG")


def pairs():
    out = []
    for s in SUITES:
        S = suite(s)
        uts = sorted(S.user_tasks, key=lambda x: int(x.split("_")[-1]))
        its = sorted(S.injection_tasks, key=lambda x: int(x.split("_")[-1]))
        for i, ut in enumerate(uts):
            out.append((s, ut, None))
            # ordered de-duplication (a set literal would make the order depend on PYTHONHASHSEED)
            for it in dict.fromkeys([its[i % len(its)], its[(i + len(its) // 2) % len(its)]]):
                out.append((s, ut, it))
    return out


def main():
    global DEFENSES
    if os.environ.get("TW_ARMS"):
        DEFENSES = os.environ["TW_ARMS"].split(",")
    model = sys.argv[1]
    from harness import LOCAL_PORTS
    port = LOCAL_PORTS.get(model) or (8021 if model == "qwen3-8b-local" else None)
    if port:  # record what the server actually serves on every row
        import urllib.request
        root = json.load(urllib.request.urlopen(f"http://localhost:{port}/v1/models", timeout=10))["data"][0]["root"]
        os.environ["SERVED_ROOT"] = root
        print(model, "served_root", root, flush=True)
    workers = int(sys.argv[2]) if len(sys.argv) > 2 else 16
    reps = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    done = set()
    for path in [LOG] + ([NEW_LOG] if NEW_LOG else []):
        if not os.path.exists(path):
            continue
        for l in open(path):
            r = json.loads(l)
            if r["model"] == model and r["err"] is None:
                done.add((r["defense"], r["suite"], r["ut"], r["it"], r["tag"]))
    jobs = [(d, s, ut, it, f"tw_r{k}") for k in range(reps) for d in DEFENSES for (s, ut, it) in pairs()
            if (d, s, ut, it, f"tw_r{k}") not in done]
    print(model, "todo", len(jobs), flush=True)
    n = [0]
    lk = threading.Lock()

    def go(j):
        d, s, ut, it, tag = j
        r = run_pair(model, s, ut, it, default_injection(s, it) if it else None, defense=d, log=NEW_LOG or LOG, tag=tag)
        with lk:
            n[0] += 1
            if n[0] % 50 == 0:
                print(model, n[0], "/", len(jobs), flush=True)
        return r["err"]
    with ThreadPoolExecutor(workers) as ex:
        errs = [e for e in ex.map(go, jobs) if e]
    print(model, "finished, errors", len(errs), errs[:3], flush=True)


if __name__ == "__main__":
    main()
