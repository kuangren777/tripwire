"""TripWire v2 candidate rules (af-man #524), designed on the E1 development traces only. Still no model call.

  R1  read locators: the locator argument of a read tool that fetches from an address (get_webpage.url) is a
      control argument with typed-only trust (USER or STRUCTURED); a fetch to an address copied out of tool text
      is refused.
  R2  anchoring: every side-effecting call needs at least one argument whose value is anchored to the user
      (source USER, or a locator the user named). A write whose arguments all come from tool text is refused.
  AMB AMBIGUOUS values join the write-back taint set, like FREE_TEXT and NONE.
  deleg=False drops delegation (DELEGATED counts as tainted), as v1's nodeleg/strict.

TripWireV2(mode, r1, r2, amb) composes these on top of v1's TripWireExecutor; with all flags off it is v1.
"""
from __future__ import annotations

from tripwire import (CONTROL_ARGS, CREDENTIAL_ARGS, DOC_ARGS, TYPED_ONLY_ARGS, Provenance, TripWireExecutor,
                      _values, canon, norm, tool_result_to_str)
from tripwire_agentdyn import (CONTENT_WRITES_AGENTDYN, CONTROL_ARGS_AGENTDYN, CREDENTIAL_ARGS_AGENTDYN,
                               DOC_ARGS_AGENTDYN, READ_LOCATORS_AGENTDYN, TYPED_ONLY_ARGS_AGENTDYN)

READ_LOCATORS: dict[str, tuple[str, ...]] = {"get_webpage": ("url",), **READ_LOCATORS_AGENTDYN}
# side-effecting tools without a v1 control argument (content-only writes)
CONTENT_WRITES: dict[str, tuple[str, ...]] = {
    "send_channel_message": ("channel", "body"),
    "create_calendar_event": ("title", "start_time", "end_time", "description", "participants", "location"),
}
# AgentDojo (v1 tables) plus AgentDyn (tripwire_agentdyn.py); no tool name has different roles in the two
CONTROL_ALL = {**CONTROL_ARGS, **CONTROL_ARGS_AGENTDYN}
CONTROL_ALL["create_calendar_event"] = CONTROL_ARGS["create_calendar_event"]
CREDENTIAL_ALL = CREDENTIAL_ARGS | CREDENTIAL_ARGS_AGENTDYN
TYPED_ONLY_ALL = TYPED_ONLY_ARGS | TYPED_ONLY_ARGS_AGENTDYN
DOC_ALL = DOC_ARGS | DOC_ARGS_AGENTDYN
CONTENT_WRITES = {**CONTENT_WRITES_AGENTDYN, **CONTENT_WRITES}
SIDE_EFFECT = set(CONTROL_ALL) | set(CONTENT_WRITES)
MIN_ANCHOR = 3   # characters; shorter values (numbers like 1, "a") never anchor a call


class ProvenanceV2(Provenance):
    def __init__(self, user_text, use_compact=True, use_taint=True, amb=False):
        super().__init__(user_text, use_compact, use_taint)
        self.amb = amb
        self.ua_struct = set()   # v2c (af-man #1009): typed values that come from USER-AUTHORED records

    def note_args(self, args: dict):
        if not self.use_taint:
            return
        bad = ("FREE_TEXT", "NONE", "AMBIGUOUS") if self.amb else ("FREE_TEXT", "NONE")
        for v in args.values():
            for x in _values(v):
                if isinstance(x, str) and self.source(x) in bad:
                    self.tainted.add(norm(x))

    def ua_extract(self, res):
        """v2c: destinations in records the user authored. Suite extractor (HISTORY) applied to EVERY result;
        slack and travel have no user-authored store, so their STRUCTURED values all fail v2c."""
        if not self.history:
            return
        fn, extract = self.history
        for v in extract(res):
            if v:
                self.ua_struct.add(canon(norm(str(v))))

    def add_call_result(self, args: dict, res):
        """v1's rule with the merged locator-argument set (DOC_ALL)."""
        if self.v2c:
            self.ua_extract(res)
        self._into_deleg = any(k in DOC_ALL and any(self.source(x) == "USER" for x in _values(v))
                               for k, v in args.items())
        try:
            self.add_result(res)
            if self._into_deleg:
                try:
                    txt = tool_result_to_str(res)
                except TypeError:
                    txt = str(res)
                self.deleg_docs.append(norm(txt))
        finally:
            self._into_deleg = False


class TripWireV2(TripWireExecutor):
    def __init__(self, mode="block", r1=False, r2=False, amb=False, r1_deleg=False, r2_free=False,
                 history=None, v2c=False, **kw):
        super().__init__(mode=mode, **kw)
        self.history, self._hist_done = history, False   # history = (tool_name, extract) or None
        self.v2c = v2c
        self.r1, self.r2, self.amb = r1, r2, amb
        self.r1_deleg = r1_deleg   # R1b: a read locator may also come from a document the user named (delegation on)
        self.r2_free = r2_free     # R2b: refuse only when no argument is anchored AND some argument is copied tool text

    def query(self, query, runtime, env, messages=(), extra_args={}):
        if self.prov is None:
            self.prov = ProvenanceV2(query, self.use_compact, self.use_taint, self.amb)
            self.prov.history = self.history
            self.prov.v2c = self.v2c
        if self.history and not self._hist_done:
            self._hist_done = True
            from tripwire import canon, norm
            fn, extract = self.history
            res, err = runtime.run_function(env, fn, {})
            if err is None:
                for v in extract(res):
                    if v:
                        self.prov.struct.add(canon(norm(str(v))))
        return super().query(query, runtime, env, messages, extra_args)

    def anchored(self, args: dict) -> bool:
        """USER, or (with delegation on) DELEGATED: a value from a document the user named."""
        ok = ("USER",) if self.mode in ("strict", "nodeleg") else ("USER", "DELEGATED")
        for v in args.values():
            for x in _values(v):
                if len(str(x).strip()) >= MIN_ANCHOR and self.prov.source(x) in ok:
                    return True
        return False

    def copied_text(self, args: dict) -> bool:
        return any(self.prov.source(x) in ("FREE_TEXT", "AMBIGUOUS") for v in args.values() for x in _values(v)
                   if len(str(x).strip()) >= MIN_ANCHOR)

    def check_v1(self, fn: str, args: dict) -> list[str]:
        """v1's check with the merged tables (identical to v1 on banking/slack/travel)."""
        deny = {"strict": {"FREE_TEXT", "AMBIGUOUS", "DELEGATED", "NONE"},
                "nodeleg": {"FREE_TEXT", "AMBIGUOUS", "DELEGATED"}}.get(self.mode, {"FREE_TEXT", "AMBIGUOUS"})
        bad, srcs = [], {}
        for a in CONTROL_ALL.get(fn, ()):
            ss = [self.prov.source(v) for v in _values(args.get(a))]
            if self.v2c:
                from tripwire import canon as _canon
                ss = ["FREE_TEXT" if x == "STRUCTURED" and _canon(norm(str(v))) not in self.prov.ua_struct
                      else x for x, v in ((self.prov.source(v), v) for v in _values(args.get(a)))]
            if ss:
                srcs[a] = ss
            if (any(x in deny for x in ss)
                    or ((fn, a) in CREDENTIAL_ALL and any(x != "USER" for x in ss))
                    or ((fn, a) in TYPED_ONLY_ALL and any(x not in ("USER", "STRUCTURED") for x in ss))):
                bad.append(a)
        if fn in CONTROL_ALL:
            self.calls.append({"f": fn, "src": srcs})
        return bad

    def check(self, fn: str, args: dict) -> list[str]:
        bad = self.check_v1(fn, args)
        if self.r1 and fn in READ_LOCATORS:
            ok = ("USER", "STRUCTURED", "DELEGATED") if self.r1_deleg and self.mode not in ("strict", "nodeleg") else ("USER", "STRUCTURED")
            for a in READ_LOCATORS[fn]:
                if any(self.prov.source(x) not in ok for x in _values(args.get(a))):
                    bad.append(a)
        if self.r2 and fn in SIDE_EFFECT and not bad and not self.anchored(args):
            if not self.r2_free or self.copied_text(args):
                bad.append("<no argument from the user>")
        return bad


# history corroboration (v2 amendment): the only records that count are ones the USER authored. A value from a
# delegated document is admitted by the hist arm only if it also appears as a destination the user themselves
# produced: the recipient of an outgoing transaction (sender "me"), or a recipient of a sent e-mail. Received
# records (incoming transactions, received e-mail senders) are attacker-seedable and never count; condition c_h
# of E2X checks exactly this. One deterministic read-tool call per task, still no model call.
HISTORY: dict[str, tuple[str, object]] = {
    "banking": ("get_most_recent_transactions",
                lambda res: [t.recipient for t in (res or []) if getattr(t, "sender", None) == "me"]),
    "dailylife": ("get_sent_emails",
                  lambda res: [r for e in (res or []) for r in (getattr(e, "recipients", None) or [])]),
}


ARMS = {   # dev-set arms: name -> constructor kwargs
    "v1": dict(mode="block"),
    "v1_strict": dict(mode="strict"),
    "v1_r1": dict(mode="block", r1=True),
    "v1_r2": dict(mode="block", r2=True),
    "v1_amb": dict(mode="block", amb=True),
    "v2_deleg": dict(mode="block", r1=True, r2=True, amb=True),
    "v2_strict": dict(mode="strict", r1=True, r2=True, amb=True),
    "v1_r1b": dict(mode="block", r1=True, r1_deleg=True),
    "v1_r2b": dict(mode="block", r2=True, r2_free=True),
    "v2b_deleg": dict(mode="block", r1=True, r1_deleg=True, r2=True, r2_free=True, amb=True),
    "v2b_strict": dict(mode="strict", r1=True, r2=True, r2_free=True, amb=True),
    # hist (E2X amendment 2, af-man #770): STRICT plus history corroboration - a relaxation of strict, not a
    # tightening of nodeleg. Strict denies FREE_TEXT, AMBIGUOUS, DELEGATED and NONE; the history loader puts
    # corroborated values into prov.struct first, and source() checks STRUCTURED before DELEGATED, so exactly the
    # user-authored-corroborated values pass. Model-fabricated values (NONE) stay denied - the guessed-address
    # cells of the archived v1 run showed why that must hold.
    "v2b_hist": dict(mode="strict", r1=True, r2=True, r2_free=True, amb=True),
    # v2c (post-hoc fix of the c_h finding, af-man #1009): STRUCTURED admits only USER-AUTHORED record values
    # (same extractor as history, applied to every result). Never swapped into H1; amendment 4 governs it.
    "v2c_strict": dict(mode="strict", r1=True, r2=True, r2_free=True, amb=True, v2c=True),
}
