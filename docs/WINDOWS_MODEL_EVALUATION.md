# Windows local-model evaluation results

These are historical synthetic measurements, not active deployment settings or authorization records. See [Windows setup](WINDOWS.md) for operating modes and consolidated verification status. No tested model established reliable investigation quality.

## Shared controls

- Actual Windows Ollama inference reached from WSL through loopback stdio transport.
- Full evidence retained; 8,192-token context and 1,024-token output budget.
- One shared inference lock, no parallel model requests or automatic retries, 120-second per-request deadline.
- Configured/returned model identity checked; truncation and context shifting disabled.
- Unchanged structured facts, evidence coverage, approval and rollback safeguards.
- Three synthetic base scenarios and relevant boundary cases; expected labels were not supplied as model instructions.
- Model agreement, structured acceptance and supported prose were assessed separately. No evaluator invoked guest traffic, Telegram or firewall operations.

## Measured candidates

| Model | Measured result | Latency / memory observations |
| --- | --- | --- |
| gemma3:1b | Repeated unsupported interpretations of approved scope, authentication outcomes and root attempts; not qualified | Earlier evaluations 35.83–83.197 s; approximately 1–1.2 GiB runner working set |
| qwen2.5:1.5b | 6/6 structured responses accepted, but only 1/6 judged adequately grounded; repeated Benign answers despite scope violations | 26.224–64.977 s; approximately 1.44 GiB runner working set |
| gemma3:latest (3.9B) | 5/6 structured responses accepted; approved case timed out and other explanations/actions failed review; no fully usable result in that evaluation | Completed calls 99.641–116.966 s; approximately 4.64 GiB peak working set |
| qwen3:4b-instruct-2507-q4_K_M | Did not pass complete qualification; see [detailed results](WINDOWS_QWEN3_EVALUATION.md) | Approximately 4.15 GiB peak working set; some calls exceeded 120 s |

Measurements depend on thread count, cache state and host/guest memory pressure. Model download size, Ollama allocation and process working set are different quantities. A faster isolated probe does not replace a failed complete evaluation.

## Gemma3 identity and context

The tested 1B model was gemma3:1b, 999.89M parameters, Q4_K_M, 806067407 bytes, digest `97558784bdc9175075a72655bf360b15da17df6b3b9e5182af9f8c0c8e58ba7c`. The separately installed gemma3:latest was 3.9B; it was not renamed to imply a 1B test.

A deliberate 30,010-token synthetic input in a 2,048-token context was rejected with HTTP 400 rather than accepted with silently missing evidence. Production-size evaluations also verified complete prompt tokens plus reserved output against configured capacity. No context-overflow result was relabelled as successful inference.

## Judgment and prose failures

Observed failures included calling permitted test activity out of scope, describing failed logins as successful, denying a recorded root-scope violation, inventing plan comparisons, and producing action-enum strings instead of useful recommendations. The facts object is bound to observed values; correct fact fields alone do not establish that the model interpreted them correctly.

Missing/partial evidence and malformed-output checks failed closed. Regex prose guards catch some contradictions but are not a general factual-entailment verifier. Keep failures visible; do not force reference verdicts, rewrite outputs as successes or loosen checks to qualify a smaller model.

The later [prompt diagnosis](WINDOWS_PROMPT_DIAGNOSIS.md) separated prompt clarity from schema consistency. Its stronger evaluation-only schema removed verdict/action conflicts in six calls but did not repair reasoning reliability. It was not activated as a quality fix.

## Reproduction

From WSL in a configured source checkout, use the public evaluators. Candidates affect only the evaluation process, not active profile files:

```sh
python3 verify_gemma.py --model gemma3:1b --output verification-model-base.json
python3 evaluate_model_boundaries.py --model gemma3:1b --output verification-model-boundaries.json
```

Use `--threads`, `--claims-first` or `--instruction-file` only as explicit controlled variables. Preserve raw results locally, record model identity, prompt/schema hashes, context/output budgets, cache state and resource measurements. Evaluate new cases without disclosing their reference labels in the prompt. Detailed raw receipts and troubleshooting history are private artifacts, not setup dependencies or release assets.
