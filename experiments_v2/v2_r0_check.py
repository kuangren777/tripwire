"""R0 gate for EXPERIMENT_PLAN_v2.md §2: ROPE's runs/aggregate.py definition (unweighted mean over the three AgentDyn
suites, ASR through runs/corrections.py) applied to our rope logs, against ROPE's shipped logs for the same model.
Pass iff |ASR diff| <= 5 pp and |CU diff| <= 10 pp. usage: python3 v2_r0_check.py"""
import glob, json, re, sys
sys.path.insert(0, "../ext/rope/runs")
from corrections import corrected_security  # noqa: E402

D = "./data/v2_heldout"
R = "../ext/rope/runs"
SUITES = ["shopping", "github", "dailylife"]
SHIPPED = {"gpt-4o-mini-2024-07-18": "gpt-4o-mini", "gpt-4o-2024-08-06": "gpt-4o", "qwen3-235b-a22b-instruct-2507": "qwen3-235b"}


def agg(clean, att):
    cu = sum(bool(json.load(open(f)).get("utility")) for f in clean) / len(clean)
    asr = sum(bool(corrected_security(json.load(open(f)), s, int(re.sub(r"\D", "", f.rsplit("/", 1)[1]) or -1))) for f, s in att) / len(att)
    return 100 * cu, 100 * asr, len(clean), len(att)


def ours(model, s):
    base = f"{D}/{model}/rope/*/{s}/user_task_*"
    return glob.glob(f"{base}/none/*.json"), [(f, s) for f in glob.glob(f"{base}/important_instructions/*.json")]


def shipped(model, s):
    base = f"{R}/{SHIPPED[model]}/{s}/user_task_*"
    return glob.glob(f"{base}/none/*.json"), [(f, s) for f in glob.glob(f"{base}/important_instructions/*.json")]


for m in SHIPPED:
    o = [agg(*ours(m, s)) for s in SUITES]; r = [agg(*shipped(m, s)) for s in SUITES]
    ocu, oasr = sum(x[0] for x in o) / 3, sum(x[1] for x in o) / 3
    rcu, rasr = sum(x[0] for x in r) / 3, sum(x[1] for x in r) / 3
    ok = abs(oasr - rasr) <= 5 and abs(ocu - rcu) <= 10
    print(f"{m:30} ours CU {ocu:5.1f} ASR {oasr:4.1f} (n {[x[2:] for x in o]}) | shipped CU {rcu:5.1f} ASR {rasr:4.1f} | "
          f"dCU {ocu-rcu:+.1f} dASR {oasr-rasr:+.1f} -> {'PASS' if ok else 'FAIL'}")
    for s, x, y in zip(SUITES, o, r):
        print(f"   {s:9} ours CU {x[0]:5.1f} ASR {x[1]:4.1f}  shipped CU {y[0]:5.1f} ASR {y[1]:4.1f}")
