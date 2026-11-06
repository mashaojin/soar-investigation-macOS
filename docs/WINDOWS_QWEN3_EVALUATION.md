# Qwen3 Windows evaluation: not qualified

`qwen3:4b-instruct-2507-q4_K_M` was evaluated after the
smaller candidates and installed larger Gemma failed readiness. It was downloaded
and tested without activating it. Installed identity: 4.0B Q4_K_M, 2497293803 bytes,
digest `0edcdef34593eac1aa2be9c7d06c432dcf81945adca5eca2f27662c18f168ba0`.

All three Hyper-V guests were shut down by the operator. Requests used Windows
Ollama through the existing WSL-to-Windows loopback transport: one request at a
time, temperature 0, 8192 context, 1024 output, thinking disabled, truncation
disabled, unchanged factual/coverage/approval safeguards and a 120-second limit.
The facts-first candidate and claims-first schema ordering were the same as in
the previous comparisons. No expected verdicts were supplied to the model.

## Two complete qualifications and one separate probe

| Fixture | Two-thread result | Four-thread result |
| --- | --- | --- |
| Approved soc_test | Timeout at 120-second limit | Timeout at 120-second limit |
| Root scope violation | SUSPICIOUS, 101.258 s | SUSPICIOUS, 97.345 s |
| Unapproved activity | INSUFFICIENT_EVIDENCE, 82.121 s | INSUFFICIENT_EVIDENCE, 81.363 s |
| Outside approved window | INSUFFICIENT_EVIDENCE, 63.491 s | INSUFFICIENT_EVIDENCE, 56.744 s |
| Single unexpected root attempt | SUSPICIOUS, 96.461 s | SUSPICIOUS, 89.240 s |
| Consolidated alerts | INSUFFICIENT_EVIDENCE, 80.508 s | INSUFFICIENT_EVIDENCE, 79.933 s |

Each six-case qualification returned five valid structured responses, two
reference-label matches, three conservative reference mismatches and one timeout.
Neither complete qualification passed. Token metrics for the timed-out cases
were unavailable; no verdicts or metrics were inferred from them.

Between the runs, one targeted four-thread approved-case probe reloaded the
runner and returned a supported BENIGN assessment in **105.070 seconds**. The
operating system's file cache was not controlled. This single success did not
reproduce in the subsequent complete four-thread run. It was preserved separately
and was not substituted for either timed-out qualification result. Total actual
assessment requests: **13**, all synthetic.

## Judgment and explanation review

The two root cases correctly identified root outside a soc_test-only plan and
did not claim successful login or compromise. Recommendations were readable
operator guidance, an improvement over larger Gemma's action-code strings.

All no-plan cases requested more evidence. That is conservative uncertainty,
**not automatically an unsafe judgment**. It nevertheless differs from the
fixtures' Suspicious reference and does not reproduce the intended demonstration
outcomes. Consolidating the same failures retained the uncertain conclusion;
there was no flip to Benign as seen with larger Gemma.

Explanation limitations remain. Describing eight failures “for admin and root”
is ambiguous when the actual total is sixteen, eight for each account. A missing
matching test plan does not establish global account authorization. An empty
unexpected_accounts list with no matching plan is not proof of clean scope. The
out-of-window explanation asserted distribution/concentration not established by
the summary; the four-thread consolidated explanation called failures within
scope despite no matching plan. Existing typed facts stayed correct, but the
free prose still needs review. The validators are not complete natural-language
entailment checkers.

Recommendations and REQUEST_MORE_EVIDENCE are distinct from firewall approval.
No output from these runs requested a real action or authorized one. A cautious
verdict cannot be relabelled Suspicious to satisfy a fixture, and matching a
verdict label would not by itself certify an explanation.

## Budgets, memory and regression verification

Completed qualification calls used at most 1022 prompt tokens. Maximum output
was 216 tokens with two threads and 232 with four, within the configured budgets.
Missing/partial coverage still entered manual review without inference; malformed
output was rejected. Those safety checks passed in both boundary suites.

Ollama's loaded allocation was 3888675552 bytes (3.62 GiB), CPU only. Windows
process samples every two seconds reached:

| Counter | Two threads | Four threads |
| --- | --- | --- |
| Maximum sampled working set | 4447739904 bytes (4.14 GiB) | 4460388352 bytes (4.15 GiB) |
| Maximum sampled private memory | 4553789440 bytes | 4567441408 bytes |
| Peak working-set counter | 4459606016 bytes | 4465201152 bytes |
| Host free physical memory after suite | 2729496 KiB | 2570512 KiB |

These are process counters, not a continuous allocation profiler. All guests
were off; memory/latency alongside the live VMs remain unverified. Download size
does not describe runtime working set. After completion the model was unloaded,
no model remained loaded, and Windows reported 6976096 KiB free.

The Windows CPU thread count is now a bounded trusted configuration option,
integer 1–4, with the previous two-thread default retained. Evaluation CLI
overrides do not write active configuration. **285 offline tests passed** after
this change, including invalid-thread rejection, configuration mismatch rejection,
identity checks and context/output safeguards. Existing Mac defaults remain.

## Status and next decision

The active profile still selects `gemma3:1b`. Qwen3 was not activated. Model
readiness remains false, live activation remains unset, and responses stay
dry-run. No VM traffic, Telegram notifications or firewall actions occurred in
these evaluations. The original staged gate for verified AI before rehearsal is
unmet. An experimental human-review demonstration would require the operator to
explicitly accept that revised scope; it must not be recorded as passing the AI
stage or authorize live enforcement. Further unrestricted model downloads are
not a substitute for this decision.

These results do not authorize activation or live enforcement. Detailed raw receipts are local-only and excluded from publication. Synthetic fixtures are not a general security benchmark.
