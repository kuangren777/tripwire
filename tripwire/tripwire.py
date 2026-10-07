"""TripWire: argument-provenance check at the tool-call boundary.

Before a side-effecting tool call executes, every *control argument* (the argument that decides
where the effect lands: recipient, email, url, user, password, file/event id, booked venue) is
traced back to where its value entered the context:

  USER        appears in the user's request                       -> allowed
  STRUCTURED  equals a short typed field of an earlier tool result -> allowed
              (e.g. a contact's email, a transaction's IBAN field)
  FREE_TEXT   appears only inside a free-text field of a tool result -> tainted
              (email body, file content, webpage, review, message, subject)
  DELEGATED   appears only in a document the user named in the request (a file path, URL or
              file id from the request) -> allowed; the user delegated that document
  NONE        not seen anywhere (model produced it)                -> allowed

A call with any tainted control argument is not executed. The agent receives a tool error that
names the argument, so it can continue the rest of the task. No extra model call, no re-execution.

mode="block" enforces; mode="nodeleg" enforces without delegation (DELEGATED counts as tainted);
mode="strict" is nodeleg and also blocks control values seen nowhere (NONE), which closes the
encode-the-value bypass at a utility cost; mode="monitor" only records what would have been blocked (used on the
undefended runs so detection can be scored on exactly the same executions).
"""
from __future__ import annotations

import re
from ast import literal_eval

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.tool_execution import ToolsExecutor, is_string_list, tool_result_to_str
from agentdojo.types import ChatToolResultMessage, text_content_block_from_string
from pydantic import BaseModel

# control arguments of every side-effecting tool in AgentDojo v1.2 (banking, slack, travel, workspace)
CONTROL_ARGS: dict[str, tuple[str, ...]] = {
    "send_money": ("recipient",),
    "schedule_transaction": ("recipient",),
    "update_scheduled_transaction": ("recipient",),
    "update_password": ("password",),
    "update_user_info": ("first_name", "last_name", "street", "city"),
    "add_user_to_channel": ("user",),
    "invite_user_to_slack": ("user", "user_email"),
    "remove_user_from_slack": ("user",),
    "send_direct_message": ("recipient",),
    "post_webpage": ("url",),
    "send_email": ("recipients", "cc", "bcc"),
    "share_file": ("email",),
    "create_calendar_event": ("participants",),
    "add_calendar_event_participants": ("participants",),
    "delete_email": ("email_id",),
    "delete_file": ("file_id",),
    "cancel_calendar_event": ("event_id",),
    "reserve_hotel": ("hotel",),
    "reserve_car_rental": ("company",),
    "reserve_restaurant": ("restaurant",),
}

# trust level per control argument (default: a delegated document may supply it)
#   user : only the user's request          (credentials)
#   typed: user request or typed record field, never document text (destinations that upload data)
CREDENTIAL_ARGS = {("update_password", "password")}
TYPED_ONLY_ARGS = {("post_webpage", "url")}

# locator arguments of read calls; if the user named the locator (a file, page, channel, inbox or
# search phrase), the user delegated what the call returns
DOC_ARGS = {"file_path", "url", "file_id", "filename", "channel", "user", "query"}

# value classes for the ambiguity rule: a delegated document may supply a destination of one of
# these classes only if it holds exactly one distinct value of that class
CLASSES = {
    "iban": re.compile(r"\b[a-z]{2}\d{2}[a-z0-9]{10,30}\b"),
    "email": re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"),
    "url": re.compile(r"(?:https?://|www\.)[^\s'\"<>,;)]+"),
}

# fields whose values are prose written by third parties
FREE_KEYS = {"content", "body", "description", "subject", "message", "text", "reviews", "review",
             "title", "notes", "summary"}
MAX_STRUCT_TOKENS = 6


def norm(v) -> str:
    return " ".join(str(v).lower().split())


def canon(v: str) -> str:
    """URL form used for matching: no scheme, no trailing slash or dot."""
    v = re.sub(r"^https?://", "", v)
    return v.rstrip("/.")


def value_class(v: str):
    for name, rx in CLASSES.items():
        if rx.fullmatch(v):
            return name
    return None


def compact(v) -> str:
    """Letters and digits only: defeats spacing / dash / case obfuscation of a value."""
    return "".join(ch for ch in str(v).lower() if ch.isalnum())


def _values(v):
    if v is None:
        return []
    if isinstance(v, (list, tuple, set)):
        return [x for x in v if x is not None and str(x).strip()]
    if isinstance(v, str) and is_string_list(v):
        try:
            return [x for x in literal_eval(v) if x is not None]
        except Exception:  # noqa: BLE001
            return [v]
    return [v] if str(v).strip() else []


class Provenance:
    """Index of where values appeared: the user request, typed fields, free-text fields."""

    def __init__(self, user_text: str, use_compact: bool = True, use_taint: bool = True):
        self.use_compact, self.use_taint = use_compact, use_taint
        self.user = norm(user_text)
        self.user_c = compact(user_text)
        self.struct: set[str] = set()
        self.free: list[str] = []
        self.free_c: list[str] = []
        self.deleg: list[str] = []       # free text of documents the user named in the request
        self.deleg_c: list[str] = []
        self.deleg_docs: list[str] = []  # whole text of each delegated call result (ambiguity rule)
        self._into_deleg = False
        self.tainted: set[str] = set()   # values the agent copied out of free text into any tool argument

    def add_result(self, obj, key: str | None = None):
        if isinstance(obj, BaseModel):
            for k in type(obj).model_fields:
                self.add_result(getattr(obj, k), k)
        elif isinstance(obj, dict):
            for k, v in obj.items():
                self.add_result(k, None)
                self.add_result(v, str(k))
        elif isinstance(obj, (list, tuple, set)):
            for x in obj:
                self.add_result(x, key)
        elif obj is None:
            return
        else:
            s = norm(obj)
            if not s:
                return
            if (key or "").lower() in FREE_KEYS or len(s.split()) > MAX_STRUCT_TOKENS:
                if self._into_deleg:
                    self.deleg.append(s)
                    self.deleg_c.append(compact(s))
                else:
                    self.free.append(s)
                    self.free_c.append(compact(s))
            else:
                self.struct.add(s)

    def source(self, value) -> str:
        v, c = canon(norm(value)), compact(canon(norm(value)))
        if not v:
            return "NONE"
        k = self.use_compact and len(c) >= 6
        if v in self.user or (k and c in self.user_c):
            return "USER"
        if v in self.struct and v not in self.tainted:
            return "STRUCTURED"
        if any(v in f for f in self.free) or v in self.tainted:
            return "FREE_TEXT"
        if k and any(c in f for f in self.free_c):
            return "FREE_TEXT"
        if any(v in f for f in self.deleg) or (k and any(c in f for f in self.deleg_c)):
            cls = value_class(v)
            if cls:
                for d in self.deleg_docs:
                    if v in d and len({canon(x) for x in CLASSES[cls].findall(d)}) > 1:
                        return "AMBIGUOUS"
            return "DELEGATED"
        return "NONE"

    def add_call_result(self, args: dict, res):
        """A result is a delegated document when the call named one document the user named."""
        self._into_deleg = any(k in DOC_ARGS and any(self.source(x) == "USER" for x in _values(v))
                               for k, v in args.items())
        try:
            self.add_result(res)
            if self._into_deleg:
                try:
                    txt = tool_result_to_str(res)
                except TypeError:  # plain dicts / lists in tests and custom tools
                    txt = str(res)
                self.deleg_docs.append(norm(txt))
        finally:
            self._into_deleg = False

    def note_args(self, args: dict):
        """Write-back taint: a string the agent writes into ANY argument, copied out of free text or
        produced by the agent itself, stays tainted when it later comes back as a typed field
        (e.g. a file name or a contact entry). Values that came from the user or typed fields stay clean."""
        if not self.use_taint:
            return
        for v in args.values():
            for x in _values(v):
                if isinstance(x, str) and self.source(x) in ("FREE_TEXT", "NONE"):
                    self.tainted.add(norm(x))


class TripWireExecutor(ToolsExecutor):
    def __init__(self, mode: str = "block", formatter=tool_result_to_str, use_compact: bool = True,
                 use_taint: bool = True):
        super().__init__(formatter)
        self.mode = mode
        self.use_compact, self.use_taint = use_compact, use_taint
        self.prov: Provenance | None = None
        self.flags: list[dict] = []        # one entry per call with a blocked/would-block control argument
        self.calls: list[dict] = []        # every side-effecting call: source of each control argument

    def check(self, fn: str, args: dict) -> list[str]:
        deny = {"strict": {"FREE_TEXT", "AMBIGUOUS", "DELEGATED", "NONE"},
                "nodeleg": {"FREE_TEXT", "AMBIGUOUS", "DELEGATED"}}.get(self.mode, {"FREE_TEXT", "AMBIGUOUS"})
        bad, srcs = [], {}
        for a in CONTROL_ARGS.get(fn, ()):
            ss = [self.prov.source(v) for v in _values(args.get(a))]
            if ss:
                srcs[a] = ss
            if (any(x in deny for x in ss)
                    or ((fn, a) in CREDENTIAL_ARGS and any(x != "USER" for x in ss))
                    or ((fn, a) in TYPED_ONLY_ARGS and any(x not in ("USER", "STRUCTURED") for x in ss))):
                bad.append(a)
        if fn in CONTROL_ARGS:
            self.calls.append({"f": fn, "src": srcs})
        return bad

    def query(self, query, runtime, env, messages=(), extra_args={}):
        if self.prov is None:
            self.prov = Provenance(query, self.use_compact, self.use_taint)
        if not messages or messages[-1]["role"] != "assistant" or not messages[-1]["tool_calls"]:
            return query, runtime, env, messages, extra_args
        results = []
        for tc in messages[-1]["tool_calls"]:
            if tc.function not in (t.name for t in runtime.functions.values()):
                results.append(ChatToolResultMessage(role="tool", content=[text_content_block_from_string("")],
                                                     tool_call_id=tc.id, tool_call=tc,
                                                     error=f"Invalid tool {tc.function} provided."))
                continue
            for k, v in tc.args.items():
                if isinstance(v, str) and is_string_list(v):
                    tc.args[k] = literal_eval(v)
            bad = self.check(tc.function, dict(tc.args))
            enforce = self.mode in ("block", "nodeleg", "strict")
            if bad:
                self.flags.append({"f": tc.function, "args": bad, "blocked": enforce})
            if bad and enforce:
                results.append(ChatToolResultMessage(
                    role="tool", content=[text_content_block_from_string("")], tool_call_id=tc.id, tool_call=tc,
                    error=(f"Blocked by TripWire: the value of argument(s) {', '.join(bad)} for {tc.function} was "
                           "taken from untrusted tool output and was not given by the user. The call was not "
                           "executed. Continue the user's original task without this action.")))
                continue
            self.prov.note_args(dict(tc.args))
            res, err = runtime.run_function(env, tc.function, tc.args)
            if err is None:
                self.prov.add_call_result(dict(tc.args), res)
            results.append(ChatToolResultMessage(role="tool", content=[text_content_block_from_string(self.output_formatter(res))],
                                                 tool_call_id=tc.id, tool_call=tc, error=err))
        return query, runtime, env, [*messages, *results], extra_args
