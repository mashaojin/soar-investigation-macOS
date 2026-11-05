# Architecture and responsibilities

```text
Victim EVE JSON --SSH--> Python monitor --> durable events + correlated incidents
                                           |
                              scoped SSH journal + approved plan
                                           |
                              one bounded direct Ollama request
                                           |
                         validated AI assessment and recommendation
                                           |
                   independent response eligibility + Telegram operator
                                           |
                         dry-run record OR guarded live worker
```

## Runtime modules

| Files | Responsibility |
|---|---|
| `monitor.py`, `service_state.py` | Separate collection, analysis, Telegram and live-worker loops; one monitor lock and heartbeat |
| `live.py`, `remote_reader.py`, `collector.py` | Bounded EVE collection, stable cursor and event deduplication |
| `incidents.py`, `ssh_correlation.py`, `incident_labels.py` | Durable correlation windows, revisions, readable incident numbers |
| `ssh_evidence.py`, `ssh_auth_reader.py` | Read-only scoped victim journal summaries and coverage checks |
| `approved_plans.py`, `plan_editor.py`, `ssh_live_investigation.py` | Validated dashboard authorization and evidence preparation |
| `ssh_investigation.py`, `ssh_scenarios.py` | Shared scope comparisons and synthetic-scenario support; historical classifiers are not the active Gemma verdict |
| `analyst.py`, `ollama_analyst.py`, `assessment_facts.py` | One model request, structured facts, prose/coverage checks and manual-review failures |
| `response.py`, `telegram_client.py` | Template selection, policy gate, private-chat approval validation and the sole Telegram poller |
| `live_response.py`, `live_lab_guard.py` | Independent live worker, victim-side rollback before deny installation and response verification |
| `live_lab.py` | Connectivity probe transport reused by the live worker; its older standalone pilot CLI is not the continuous workflow |
| `human_review.py`, `report_language.py` | Append-only human conclusions, review notices/buttons and display-only plain-language formatting |
| `dashboard.py`, `dashboard_view.py`, `web/` | Loopback UI, protected mutation APIs, evidence views and workflow progress |
| `experiment_store.py`, `rule_editor.py`, `soc_rule_helper.py` | Versioned prompts, isolated comparisons and constrained victim rule deployment |

`dvwa.py` remains a shared event-sanitizing/compatibility dependency, and `plan_document.py` supports explicitly gated legacy-plan import handling. Their presence does not enable DVWA demonstrations or Word authorization in the current SSH dashboard. Obsolete demo, migration and verification entry points are archived outside the repository.

## AI versus Python

Python determines what evidence is supplied, computes scope comparisons and validates factual claims. Gemma chooses Benign, Suspicious or Insufficient Evidence and recommends Report only, Request block approval or Request more evidence. A Suricata threshold triggers collection; there is no active six-failure rule that forces the model's verdict.

Gemma has no autonomous tools, Telegram access or command execution. Python chooses the message template and inserts incident metadata, retained evidence and validated AI content. A recommendation is never approval. A valid source/target, current assessment, independent lab policy and authorized operator response are required for live execution.

## Correlation, labels and review

Unapproved scopes are fixed windows; approved scopes bind to the exact recorded plan. Additional evidence increments the incident revision. Edits to authorization during a bound investigation can require human review rather than silently reinterpret the old incident.

Public labels use `INC-YYYYMMDD-NNN`, with America/Vancouver dates from the first retained alert. The daily number persists in SQLite; late arrivals receive the next available number and do not renumber history. Historical records without retained alerts explicitly use the saved window start. Internal hash IDs continue to bind evidence, URLs, reviews and approvals.

Human review stores the operator conclusion separately from the AI report. Benign/Suspicious resolves the review; Need more evidence leaves it open. It performs no model call or extra collection and authorizes no firewall action. Telegram choices are bound to the private operator, sent message, current evidence/revision and previous review; they expire after 24 hours and are single use.

## Reproducibility boundary

Offline tests use synthetic fixtures and mocked external effects. Saved-evidence comparisons call the model with identical saved evidence and differing prompts; they cannot reproduce traffic absent from that evidence or test a new sensor rule on old traffic. New network/rule behavior requires a fresh manual lab rehearsal.
