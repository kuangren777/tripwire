"""External validity of the delegation boundary (af-man #657 item 2, #661). Read-only: walks the default
environments of the six suites, no model calls. For every user task with a ground-truth side-effect call:
  (i)   delegation: the destination value is absent from the prompt but present in a document the prompt names
        (file path, web URL, channel name, e-mail address or subject occurring verbatim in the prompt);
  (ii)  history coverage, of the (i) tasks: the destination also appears in a USER-AUTHORED record
        (banking: recipient of an outgoing transaction, sender "me"; dailylife/github: recipient of a sent
        e-mail; anything received/incoming never counts, it is attacker-seedable).
Slack, travel and shopping have no user-authored record store reachable by a tool; their (ii) is reported as
"no store" rather than 0. usage: PYTHONPATH=ext/rope/autodojo/src:ext/rope/src python3 e2x_prevalence.py"""
import json

from agentdojo.task_suite.load_suites import get_suite

from tripwire_v2 import CONTROL_ALL   # the paper's own side-effecting-tool table

VERSION = "v1.2.2"
DEST_ARGS = {"recipient", "recipients", "to", "user", "user_email", "url", "email", "cc", "bcc",
             "collaborator_email", "new_owner_username", "new_owner_email", "account"}
OUT = "./data/e2x/prevalence.json"


def docs(env):
    """identifier -> text, for every named-document-like source in the environment."""
    out = {}
    if hasattr(env, "filesystem"):
        if hasattr(env.filesystem, "files"):          # AgentDojo banking: path -> content
            out.update(env.filesystem.files)
        else:                                         # AgentDyn: directory tree
            for p, node in walk(env.filesystem.root, ""):
                if getattr(node, "type", None) == "file":
                    out[p] = node.content
    if hasattr(env, "web"):
        out.update(env.web.web_content)
    if hasattr(env, "web_database"):
        for w in env.web_database.web_list:
            out[w.web_url] = w.web_content
    if hasattr(env, "slack"):
        for ch, msgs in env.slack.channel_inbox.items():
            out[ch] = "\n".join(f"{m.sender}: {m.body}" for m in msgs)
    if hasattr(env, "email_database"):
        for ib in env.email_database.inbox_list:
            for e in ib.emails.values() if hasattr(ib.emails, "values") else ib.emails:
                out.setdefault(e.sender, "")
                out[e.sender] += f"\n{e.subject}\n{e.body}"
                for rcpt in e.recipients:
                    out.setdefault(rcpt, "")
    return out


def walk(node, path):
    if getattr(node, "type", None) == "directory" or hasattr(node, "children"):
        for name, child in (node.children or {}).items():
            yield from walk(child, f"{path}/{name}")
    else:
        yield path, node


def user_authored(env):
    """destination values the user themselves produced; received records never count."""
    vals = set()
    if hasattr(env, "bank_account"):
        for t in env.bank_account.transactions:
            if t.sender == "me":
                vals.add(str(t.recipient).lower())
        for t in getattr(env.bank_account, "scheduled_transactions", []) or []:
            if t.sender == "me":
                vals.add(str(t.recipient).lower())
    if hasattr(env, "email_database"):
        for ib in env.email_database.inbox_list:
            emails = ib.emails.values() if hasattr(ib.emails, "values") else ib.emails
            for e in emails:
                if getattr(e, "status", None) is not None and str(getattr(e.status, "value", e.status)) == "sent" \
                        and str(e.sender).lower() == str(ib.account_email).lower():
                    for r in e.recipients:
                        vals.add(str(r).lower())
    return vals


def main():
    report = {}
    for sn in ("banking", "slack", "travel", "shopping", "github", "dailylife"):
        suite = get_suite(VERSION, sn)
        env = suite.load_and_inject_default_environment({})
        D, U = docs(env), user_authored(env)
        n_eff = n_del = n_hist = 0
        rows = []
        for uid, t in suite.user_tasks.items():
            prompt = t.PROMPT.lower()
            named = [k for k in D if len(k) > 3 and (k.lower() in prompt or k.lower().removeprefix("www.") in prompt)]
            try:
                gt = t.ground_truth(env)
            except Exception:  # noqa: BLE001
                continue
            for c in gt:
                if c.function not in CONTROL_ALL:   # only side-effecting calls carry a destination
                    continue
                for a, v in (c.args or {}).items():
                    if a.lower() not in DEST_ARGS:
                        continue
                    for x in (v if isinstance(v, (list, tuple)) else [v]):
                        x = str(x)
                        if len(x) < 4 or x.lower() in prompt:
                            continue
                        n_eff += 1
                        hit = [k for k in named if x.lower() in D[k].lower()]
                        if hit:
                            n_del += 1
                            in_hist = x.lower() in U
                            n_hist += in_hist
                            rows.append({"task": uid, "tool": c.function, "arg": a, "value": x[:40],
                                         "doc": hit[:2], "user_authored_history": in_hist})
        report[sn] = {"side_effect_destinations": n_eff, "delegated": n_del, "with_user_authored_history": n_hist,
                      "user_authored_store": bool(hasattr(env, "bank_account")) or sn in ("github", "dailylife"),
                      "rows": rows}
        print(f"{sn:10} destinations {n_eff:3}  delegated {n_del:3} ({100*n_del/max(1,n_eff):.0f}%)  "
              f"of delegated in user history {n_hist}  store={'yes' if report[sn]['user_authored_store'] else 'none'}")
    tot_eff = sum(v["side_effect_destinations"] for v in report.values())
    tot_del = sum(v["delegated"] for v in report.values())
    tot_hist = sum(v["with_user_authored_history"] for v in report.values())
    # confirmation burden (af-man #699): a deployer who confirms every delegated destination once asks the user
    # exactly this many times. Counts, not only rates (n is small).
    report["confirmation_burden"] = {"side_effect_destinations": tot_eff, "need_one_confirmation": tot_del,
                                     "already_in_user_authored_history": tot_hist,
                                     "per_suite": {sn: [v["side_effect_destinations"], v["delegated"]] for sn, v in report.items()}}
    print(f"TOTAL     destinations {tot_eff:3}  delegated {tot_del:3} ({100*tot_del/max(1,tot_eff):.0f}%)  "
          f"of delegated in user history {tot_hist}")
    json.dump(report, open(OUT, "w"), indent=1)


if __name__ == "__main__":
    main()
