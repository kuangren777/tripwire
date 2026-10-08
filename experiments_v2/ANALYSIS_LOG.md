# TripWire v2 analysis log

## 2026-10-08 ~07:12 SGT - e2x_analyze.py read the wrong metric for condition a_h
Found while producing the first E2X summary, immediately after the two-model hub2 batch finished (06:43 SGT)
and BEFORE any number from any condition was reported to anyone: the loader mapped every condition other than
exactly "a" to the security field, so a_h cells reported attack success (all 0) instead of utility. Fixed in
the same session (commit 252153b3) and the corrected numbers were the first E2X numbers sent out (af-man #810,
07:18 SGT). No number derived from the buggy line was ever reported or written into any file outside this repo.

## 2026-10-08 ~07:30 SGT - rope scope cross-tabulation (af-man #811)
e2x_rope_scope.py rebuilds each task's router cache key exactly as rope.router.route_and_scope does (sha256 of
model, system, user; _SCOPE_SYSTEM + few-shot; SENSITIVE TOOLS block + trusted facts + TASK) and reads the
cached claude-opus-4-8 response. All 40 prompts resolved. Marker semantics: the override spec if present;
"unguarded" when the audited floor does not list the parameter at all; "floor" when guarded with no override.
Result: no admission anywhere the scope demanded RECORD or the floor guarded the parameter. See
data/e2x/rope_scope_xtab.json.

## 2026-10-08 ~17:55 SGT - RQ4 synthesis/reception census (af-man #1045, post-hoc by declaration)
boundary_prevalence.py, written AFTER the H1 result and the synthesis-boundary diagnosis, and marked post-hoc
wherever it appears in the paper. Metric definitions fixed before running: SYNTHESIS = a ground-truth control
value of a side-effecting call that appears neither in the prompt nor verbatim anywhere in the suite's default
environment dump, so a correct agent must compose, transform or guess it. RECEPTION = the suite's environment
exposes attacker-writable record fields (incoming transaction senders or received e-mail senders). Read-only.
Correction (af-man #1047): the census definition and its result were committed together (45c993cf); the
definition was not frozen in a separate commit before computation. The census is post-hoc wherever it appears.
Rule going forward: definitions get their own commit before any computation.
