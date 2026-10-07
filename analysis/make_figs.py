"""All data figures of the TripWire paper, read only from results.json (written by analyze.py).
Each figure is written as $TRIPWIRE_OUT/fig/<name>.pdf. Missing data -> the figure is skipped.
"""
import json
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # release root
OUT_DIR = os.environ.get("TRIPWIRE_OUT", os.path.join(HERE, "out"))
os.makedirs(os.path.join(OUT_DIR, "fig"), exist_ok=True)
J = json.load(open(os.path.join(OUT_DIR, "results.json")))
OUT = os.path.join(OUT_DIR, "fig")
plt.rcParams.update({"font.size": 8, "font.family": "serif", "axes.spines.top": False, "axes.spines.right": False,
                     "legend.frameon": False})
NAME = {"tw_monitor": "No defense", "tripwire": "TripWire (ours)", "tw_nodeleg": "TripWire w/o delegation",
        "tw_strict": "TripWire-strict", "spotlighting": "Spotlighting", "repeat_user_prompt": "Sandwich",
        "tool_filter": "Tool filter", "melon": "MELON", "pi_detector": "PI detector"}
COL = {"tw_monitor": "#9e9e9e", "tripwire": "#c0392b", "tw_nodeleg": "#e59866", "tw_strict": "#7b241c",
       "spotlighting": "#5dade2", "repeat_user_prompt": "#2e86c1", "tool_filter": "#48c9b0", "melon": "#1f618d",
       "pi_detector": "#76448a"}
BASE = ["tw_monitor", "spotlighting", "repeat_user_prompt", "tool_filter", "pi_detector", "melon", "tripwire"]
MODEL = {"gpt-5.6-sol": "GPT-5.6-sol", "gemini-3.1-pro": "Gemini-3.1-pro", "claude-sonnet-5": "Claude-Sonnet-5",
         "deepseek-v4.1-flash": "DeepSeek-v4.1", "kimi-k3": "Kimi-k3", "glm-5.3": "GLM-5.3",
         "qwen3-8b-local": "Qwen3-8B", "qwen25-7b-local": "Qwen2.5-7B", "llama31-8b-local": "Llama-3.1-8B",
         "granite31-8b-local": "Granite-3.1-8B"}


def g(*k):
    return J.get(" | ".join(k))


def save(fig, name):
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, name + ".pdf"))
    plt.close(fig)
    print("wrote", name)


def bars(ax, groups, series, value, ylabel, legend=True, ncol=4):
    """grouped bar chart; value(group, series) -> float or None"""
    w = 0.8 / len(series)
    x = np.arange(len(groups))
    for i, sname in enumerate(series):
        ys = [value(gr, sname) for gr in groups]
        ys = [np.nan if y is None else 100 * y for y in ys]
        ax.bar(x + (i - (len(series) - 1) / 2) * w, ys, w, label=NAME.get(sname, sname), color=COL.get(sname),
               edgecolor="black" if sname == "tripwire" else "none", linewidth=0.6)
    ax.set_xticks(x)
    ax.set_xticklabels(groups)
    ax.set_ylabel(ylabel)
    ax.grid(axis="y", alpha=.3, lw=.5)
    if legend:
        ax.legend(ncol=ncol, fontsize=6.5, loc="upper center", bbox_to_anchor=(0.5, 1.22))


# 1 trade-off, one panel per weak model
weak = [m for m in ("qwen3-8b-local", "qwen25-7b-local") if g(m, "tripwire")]
allweak = [m for m in ("qwen3-8b-local", "qwen25-7b-local", "llama31-8b-local", "granite31-8b-local") if g(m, "tripwire")]
if weak and g("six frontier models pooled", "tripwire"):
    fig, axs = plt.subplots(1, len(weak), figsize=(3.3 * len(weak), 2.6), squeeze=False)
    for ax, m in zip(axs[0], weak):
        for d in BASE:
            q, f = g(m, d), g("six frontier models pooled", d)
            if not q or not f:
                continue
            ours = d == "tripwire"
            if "ub_lo" in f and "asr_lo" in q:  # 95% cluster bootstrap intervals over user tasks
                ax.errorbar(100 * f["ub"], 100 * q["asr"],
                            xerr=[[100 * (f["ub"] - f["ub_lo"])], [100 * (f["ub_hi"] - f["ub"])]],
                            yerr=[[100 * (q["asr"] - q["asr_lo"])], [100 * (q["asr_hi"] - q["asr"])]],
                            fmt="none", ecolor=COL[d], elinewidth=0.6, alpha=0.6, zorder=2)
            ax.scatter(100 * f["ub"], 100 * q["asr"], s=60 if ours else 26, marker="*" if ours else "o",
                       color=COL[d], zorder=3, edgecolor="black" if ours else "none")
            off = {"tw_monitor": (4, 4), "spotlighting": (4, -9), "repeat_user_prompt": (-46, -2), "tripwire": (5, -3)}.get(d, (4, 3))
            ax.annotate(NAME[d], (100 * f["ub"], 100 * q["asr"]), textcoords="offset points", xytext=off,
                        fontsize=6.5, fontweight="bold" if ours else "normal")
        ax.set_xlabel("Benign utility on frontier models (%) $\\uparrow$")
        ax.set_ylabel(f"ASR on {MODEL[m]} (%) $\\downarrow$")
        ax.set_xlim(right=ax.get_xlim()[1] + 8)
        ax.set_ylim(bottom=0)
        ax.grid(alpha=.3, lw=.5)
    save(fig, "tradeoff")

# 2 benign utility per model and defense
models = [m for m in MODEL if g("model", m, "tw_monitor")]
if models:
    fig, ax = plt.subplots(figsize=(7, 2.5))
    bars(ax, [MODEL[m] for m in models], BASE,
         lambda grp, d: (g("model", [k for k, v in MODEL.items() if v == grp][0], d) or {}).get("ub"),
         "Benign utility (%) $\\uparrow$")
    plt.setp(ax.get_xticklabels(), rotation=18, ha="right")
    save(fig, "per_model_utility")

# 3 benign utility per suite (frontier pooled)
suites = ["banking", "slack", "travel", "workspace"]
if g("suite", "banking", "tripwire"):
    fig, ax = plt.subplots(figsize=(7, 2.3))
    bars(ax, [s.capitalize() for s in suites], BASE + ["tw_nodeleg"],
         lambda grp, d: (g("suite", grp.lower(), d) or {}).get("ub"), "Benign utility (%) $\\uparrow$", ncol=4)
    save(fig, "per_suite_utility")

# 4 ASR by attack class on open-weight models (three classes)
rows = []
for m, t in (("qwen3-8b-local", "Q"), ("qwen25-7b-local", "R"), ("llama31-8b-local", "L"), ("granite31-8b-local", "G")):
    if f"{t}valNone" in J.get("extra", {}):
        rows.append((m, t))
if rows:
    fig, axs = plt.subplots(1, 3, figsize=(7.2, 2.7))
    keymap = {"tw_monitor": "None", "tripwire": "TW", "tw_strict": "Strict"}
    for ax, (cls, title) in zip(axs, (("val", "Value attacks"), ("env", "Environment attacks"), ("noc", "No control argument"))):
        groups = [MODEL[m].replace("-Instruct", "") for m, _ in rows]
        bars(ax, groups, ["tw_monitor", "tripwire", "tw_strict"],
             lambda grp, d: float(J["extra"][[t for m, t in rows if MODEL[m].replace("-Instruct", "") == grp][0] + cls + keymap[d]]) / 100,
             "ASR (%) $\\downarrow$" if cls == "val" else "", legend=(cls == "val"), ncol=3)
        ax.set_title(title, fontsize=7.5, pad=2)
        plt.setp(ax.get_xticklabels(), rotation=25, ha="right", fontsize=6.5)
    axs[0].legend(ncol=3, fontsize=6.5, loc="upper left", bbox_to_anchor=(0.0, 1.38))
    save(fig, "attack_class")

# 5 attack templates
kinds = [("important_instructions", "Important instr."), ("tool_knowledge", "Tool knowledge"), ("injecagent", "InjecAgent")]
tmods = [m for m in weak if (g("atk", m, "tool_knowledge", "tw_monitor") or [0, 0])[1]]
if tmods:
    fig, axs = plt.subplots(1, len(tmods), figsize=(3.5 * len(tmods), 2.4), squeeze=False)
    for ax, m in zip(axs[0], tmods):
        bars(ax, [k[1] for k in kinds], ["tw_monitor", "tripwire"],
             lambda grp, d: (lambda v: v[0] if v and v[1] else None)(g("atk", m, [k for k, n in kinds if n == grp][0], d)),
             f"ASR on {MODEL[m]} (%) $\\downarrow$", legend=(m == tmods[0]), ncol=2)
    save(fig, "attack_templates")

# 6 RQ3 ablation
e = J.get("extra", {})
if g("abl", "obfuscate", "tripwire") and "TaintPaths" in e:
    fig, axs = plt.subplots(1, 2, figsize=(6.4, 2.2))
    ob = [g("abl", "obfuscate", d) for d in ("tw_monitor", "tripwire", "tw_nocompact")]
    axs[0].bar(["No defense", "TripWire", "w/o normal."], [100 * v[0] for v in ob],
               color=[COL["tw_monitor"], COL["tripwire"], "#e59866"], edgecolor=["none", "black", "none"], linewidth=.6)
    axs[0].set_ylabel("ASR, dash-split values (%) $\\downarrow$")
    axs[0].set_title("Normalization (Qwen3-8B)", fontsize=8)
    tp = e["TaintPaths"]
    axs[1].bar(["TripWire", "w/o taint"], [100 * e["TaintBlocked"] / tp, 100 * e["NoTaintBlocked"] / tp],
               color=[COL["tripwire"], "#e59866"], edgecolor=["black", "none"], linewidth=.6)
    axs[1].set_ylabel("Laundering paths blocked (%) $\\uparrow$")
    axs[1].set_title(f"Write-back taint ({tp} scripted paths)", fontsize=8)
    for ax in axs:
        ax.grid(axis="y", alpha=.3, lw=.5)
        for p_ in ax.patches:
            ax.annotate(f"{p_.get_height():.1f}", (p_.get_x() + p_.get_width() / 2, p_.get_height()),
                        ha="center", va="bottom", fontsize=6.5)
    save(fig, "ablation")

# 7 RQ4 adaptive
if g("adapt", "split", "tripwire"):
    fig, ax = plt.subplots(figsize=(4.2, 2.3))
    bars(ax, ["Split", "Launder"], ["tw_monitor", "tripwire", "tw_strict"],
         lambda grp, d: (g("adapt", grp.lower(), d) or [None])[0], "ASR on Qwen3-8B (%) $\\downarrow$", ncol=3)
    for p_ in ax.patches:
        ax.annotate(f"{p_.get_height():.1f}", (p_.get_x() + p_.get_width() / 2, p_.get_height()), ha="center", va="bottom", fontsize=6.5)
    save(fig, "adaptive")

# 8 where control values come from in benign runs
srcs = [("USER", "user request", "#27ae60"), ("STRUCTURED", "typed field", "#82e0aa"),
        ("DELEGATED", "named document", "#f7dc6f"), ("FREE_TEXT", "free text", "#e74c3c"),
        ("NONE", "model-made", "#bdc3c7")]
labels = [k for k in ("frontier", "qwen3-8b-local", "qwen25-7b-local") if g("src", k)]
if labels:
    fig, ax = plt.subplots(figsize=(5.2, 2.0))
    left = np.zeros(len(labels))
    for key, nm, c in srcs:
        vals = np.array([100 * g("src", k)[key] for k in labels])
        ax.barh([{"frontier": "Frontier models"}.get(k, MODEL.get(k, k)) for k in labels], vals, left=left, color=c, label=nm)
        left += vals
    ax.set_xlabel("Share of control-argument values in benign runs (%)")
    ax.legend(ncol=3, fontsize=6.5, loc="upper center", bbox_to_anchor=(0.45, 1.75))
    ax.set_xlim(0, 100)
    save(fig, "sources")

# 9 monitor mode: share of undefended runs TripWire would have blocked, per model
mon = [(m, g("monitor", m)) for m in ("qwen3-8b-local", "qwen25-7b-local", "llama31-8b-local", "granite31-8b-local")]
mon = [(MODEL[m], v) for m, v in mon if v] + ([("Six frontier", g("monitor", "frontier"))] if g("monitor", "frontier") else [])
if mon:
    fig, ax = plt.subplots(figsize=(7, 2.4))
    kinds = [("vval", "vval_flag", "Successful value attacks", "#c0392b"),
             ("viol", "viol_flag", "All successful attacks", "#e59866"),
             ("ben", "ben_flag", "Benign runs", "#5dade2")]
    w = 0.8 / len(kinds)
    x = np.arange(len(mon))
    for i, (n, k, lab, c) in enumerate(kinds):
        xs = x + (i - 1) * w
        for xi, (_, v) in zip(xs, mon):
            if v[n] == 0:
                ax.text(xi, 2, "n/a", ha="center", va="bottom", fontsize=5.5, rotation=90)
                continue
            y = 100 * v[k] / v[n]
            ax.bar(xi, y, w, color=c, label=lab if xi == xs[0] else None,
                   edgecolor="black" if n == "vval" else "none", linewidth=0.6)
            ax.text(xi, y + 1.5, f"{v[k]}/{v[n]}", ha="center", va="bottom", fontsize=5.5, rotation=90)
    ax.set_xticks(x)
    ax.set_xticklabels([m for m, _ in mon])
    ax.set_ylim(0, 118)
    ax.set_ylabel("Runs flagged (%)")
    ax.grid(axis="y", alpha=.3, lw=.5)
    ax.legend(ncol=3, fontsize=6.5, loc="upper center", bbox_to_anchor=(0.5, 1.2))
    save(fig, "monitor")
