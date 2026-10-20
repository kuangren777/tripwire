"""E1 analysis (EXPERIMENT_PLAN_rope.md). Reads AgentDojo result JSONs written by e_rope_run.py under data_v2/e1_rope/<model>/<arm>/.
Per (model, arm): ASR, CU, UA, raw and with ROPE's effect-based correction (runs/corrections.py; only slack IT5 applies here),
task-cluster bootstrap CIs (cluster = suite x user task, 10,000 resamples, seed 20261007), paired McNemar on attacked pairs.
usage: python3 e_rope_analyze.py [--model M ...]"""
import os as _os, sys as _sys  # release layout: modules live in these folders of the repository
_R = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_sys.path[:0] = [_os.path.join(_R, _d) for _d in ("tripwire_v2", "tripwire", "experiments_v2", "analysis_v2", "analysis_s7", "scripts", "testbed")]
import collections, glob, json, math, os, random, re, sys

sys.path.insert(0, "ext/rope/runs")
from corrections import corrected_security  # noqa: E402  (ROPE's own correction, applied to every arm)

D = os.environ.get("E1_DIR", "./data_v2/e1_rope")
ARMS = ["none", "rope", "tripwire", "tripwire_strict", "tripwire_v2", "tripwire_strict_v2"]


def load(model, arm):
    att, clean = {}, {}
    for f in glob.glob(f"{D}/{model}/{arm}/*/*/user_task_*/*/*.json"):
        p = f.split("/")
        suite, ut, attack, leaf = p[-4], p[-3], p[-2], p[-1][:-5]
        d = json.load(open(f))
        if attack == "none":
            clean[(suite, ut)] = int(bool(d.get("utility")))
        else:
            it = int(re.sub(r"\D", "", leaf) or -1)
            att[(suite, ut, leaf)] = {"util": int(bool(d.get("utility"))), "sec_raw": int(bool(d.get("security"))),
                                      "sec": int(bool(corrected_security(d, suite, it)))}
    return att, clean


def boot(vals_by_cluster, n=10000, seed=20261007):
    cs = sorted(vals_by_cluster)
    if not cs:
        return (float("nan"),) * 2
    rng = random.Random(seed); bs = []
    for _ in range(n):
        a = b = 0
        for _ in cs:
            v = vals_by_cluster[rng.choice(cs)]; a += sum(v); b += len(v)
        bs.append(a / b)
    bs.sort()
    return bs[250], bs[9749]


def mcnemar(b, c):
    n = b + c
    return 1.0 if n == 0 else min(1.0, 2 * sum(math.comb(n, i) for i in range(min(b, c) + 1)) / 2 ** n)


def main():
    models = sys.argv[sys.argv.index("--model") + 1:] if "--model" in sys.argv else sorted(m for m in os.listdir(D) if not m.startswith("_"))
    out = {}
    for m in models:
        data = {a: load(m, a) for a in ARMS if os.path.isdir(f"{D}/{m}/{a}")}
        out[m] = {}
        for a, (att, clean) in data.items():
            cl_asr, cl_ua, cl_cu = collections.defaultdict(list), collections.defaultdict(list), collections.defaultdict(list)
            for (s, ut, _), v in att.items():
                cl_asr[(s, ut)].append(v["sec"]); cl_ua[(s, ut)].append(v["util"])
            for (s, ut), v in clean.items():
                cl_cu[(s, ut)].append(v)
            n_att, n_cl = len(att), len(clean)
            e = {"n_attacked": n_att, "n_clean": n_cl,
                 "ASR": sum(v["sec"] for v in att.values()) / n_att if n_att else None,
                 "ASR_raw": sum(v["sec_raw"] for v in att.values()) / n_att if n_att else None,
                 "UA": sum(v["util"] for v in att.values()) / n_att if n_att else None,
                 "CU": sum(clean.values()) / n_cl if n_cl else None,
                 "ASR_ci": boot(cl_asr), "UA_ci": boot(cl_ua), "CU_ci": boot(cl_cu)}
            out[m][a] = e
        pairs = {}
        for a, b in [("tripwire", "rope"), ("tripwire_strict", "rope"), ("rope", "none"), ("tripwire", "none"), ("tripwire_strict", "none")]:
            if a in data and b in data:
                A, B = data[a][0], data[b][0]
                ks = set(A) & set(B)
                b10 = sum(A[k]["sec"] and not B[k]["sec"] for k in ks); b01 = sum(B[k]["sec"] and not A[k]["sec"] for k in ks)
                pairs[f"{a}_vs_{b}"] = {"n": len(ks), "a_only": b10, "b_only": b01, "p": mcnemar(b10, b01)}
        out[m]["paired_ASR"] = pairs
        for a, e in out[m].items():
            if a == "paired_ASR":
                continue
            f = lambda x: "-" if x is None else f"{100*x:.1f}"
            print(f"{m:24} {a:16} ASR {f(e['ASR'])} [{f(e['ASR_ci'][0])},{f(e['ASR_ci'][1])}] (raw {f(e['ASR_raw'])}, n={e['n_attacked']})  "
                  f"CU {f(e['CU'])} (n={e['n_clean']})  UA {f(e['UA'])}")
        for k, v in pairs.items():
            print(f"{m:24}   {k}: n={v['n']} only-first={v['a_only']} only-second={v['b_only']} p={v['p']:.3g}")
    os.makedirs(f"{D}_summary", exist_ok=True)   # data_v2/e1_rope -> data_v2/e1_rope_summary (unchanged for E1)
    json.dump(out, open(f"{D}_summary/summary.json", "w"), indent=1, default=str)


if __name__ == "__main__":
    main()
