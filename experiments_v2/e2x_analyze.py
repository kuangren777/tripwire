"""E2X analysis (EXPERIMENT_PLAN_v2.md §3). Reads data/e2x_{a,c}/<model>/<arm>/.../e2x_{a,c}/none.json.
Per (model, arm): utility in a, success in b and c. Pooled over models (pairs = task x model):
  H2a  v2b_deleg (arm tripwire_v2) utility in a exceeds rope's: one-sided exact McNemar, alpha 0.05;
  H2b  v2b_deleg success in b is at most rope's + 2 pp (pooled rates).
  c and every v2b_strict comparison are reported without a hypothesis (two-sided McNemar).
usage: python3 e2x_analyze.py -> data/e2x_summary.json"""
import glob, json, math, os

T = "./data"
ARMS = ["none", "rope", "tripwire_v2", "tripwire_strict_v2", "tripwire_hist_v2"]


def load(cond):
    out = {}
    for f in glob.glob(f"{T}/e2x_{cond}/*/*/*/*/*/e2x_{cond}/none.json"):
        p = f.split("/"); d = json.load(open(f))
        if "utility" not in d:
            continue
        model, arm, task = p[-7], p[-6], p[-3]
        out[(model, arm, task)] = bool(d["utility"] if cond in ("a", "a_h") else d["security"])
    return out


def binom_tail(k, n):   # P(X >= k), X ~ Bin(n, 1/2)
    return sum(math.comb(n, i) for i in range(k, n + 1)) / 2 ** n if n else 1.0


def mcnemar(x, y, one_sided):
    b = sum(1 for k in x if x[k] and not y[k]); c = sum(1 for k in x if y[k] and not x[k])
    p = binom_tail(c, b + c) if one_sided else min(1.0, 2 * binom_tail(max(b, c), b + c))
    return {"first_only": b, "second_only": c, "p": p}


def main():
    res = {}
    for cond in ("a", "a_h", "b", "c", "c_h"):
        D = load(cond)
        models = sorted({k[0] for k in D})
        res[cond] = {m: {a: [sum(v for k, v in D.items() if k[0] == m and k[1] == a), sum(1 for k in D if k[0] == m and k[1] == a)]
                         for a in ARMS} for m in models}
        for a in ("tripwire_strict_v2", "tripwire_v2", "tripwire_hist_v2"):
            keys = {(m, t) for (m, arm, t) in D if arm == a} & {(m, t) for (m, arm, t) in D if arm == "rope"}
            x = {k: D[(k[0], a, k[1])] for k in keys}; y = {k: D[(k[0], "rope", k[1])] for k in keys}
            h2a = cond == "a" and a == "tripwire_v2"   # one-sided: arm-only successes (first_only) exceed rope-only
            r = mcnemar(y, x, one_sided=True) if h2a else mcnemar(x, y, one_sided=False)
            if h2a:
                r = {"first_only": r["second_only"], "second_only": r["first_only"], "p": r["p"]}
            r.update(n=len(keys), rate_arm=sum(x.values()) / max(1, len(keys)), rate_rope=sum(y.values()) / max(1, len(keys)))
            if cond == "b" and a == "tripwire_v2":
                r["H2b_holds"] = (r["rate_arm"] <= r["rate_rope"] + 0.02) if keys else None
            if h2a:
                r["H2a_holds"] = (r["p"] < 0.05) if keys else None
            res[cond][f"{a}_vs_rope"] = r
        for m, r in res[cond].items():
            print(cond, m, r)
    json.dump(res, open(f"{T}/e2x_summary.json", "w"), indent=1)


if __name__ == "__main__":
    main()
