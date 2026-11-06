# Offline Gemma3 prompt/output diagnosis

Synthetic-only diagnosis of `gemma3:1b`, 8,192 context and 1,024 output tokens. No candidate was activated.

The two rejected live outputs had adequate context and complete observed coverage. Both combined Insufficient Evidence with Request Block Approval. Their missing-data explanation contradicted supplied observations; this was not prompt truncation.

## Controlled experiments

Seven actual local model calls were made: one clearer-prompt probe and six clearer-prompt plus dependent-schema probes. All requests used the existing shared inference lock and 120-second limit. Synthetic evidence and original Python validators were retained. No VM traffic, Telegram messages, cloud upload or firewall operations were invoked by the diagnosis.

The clearer prompt alone returned Benign plus Request more evidence for the root-scope fixture, with an unsupported missing-context explanation. Its JSON was accepted by the existing validator, but judgment quality failed.

The evaluation-only schema used three branches allowing all verdict choices while restricting each to compatible actions. Every branch retained the original required fields and fixed observed claims. Benign allowed Report only; Insufficient Evidence allowed Request more evidence; Suspicious allowed any of the three actions. This tightened generation constraints without forcing an expected verdict or changing Python validation.

| Synthetic case | Accepted structure | Verdict | Action | Reference label match | Seconds |
|---|---|---|---|---|---|
| scope_violation | True | SUSPICIOUS | REPORT_ONLY | True | 28.161 |
| approved_test | True | SUSPICIOUS | REQUEST_MORE_EVIDENCE | False | 59.524 |
| unapproved_activity | True | SUSPICIOUS | REPORT_ONLY | True | 53.751 |
| outside_approved_window | True | SUSPICIOUS | REPORT_ONLY | True | 55.980 |
| single_unexpected_root_attempt | True | BENIGN | REPORT_ONLY | False | 62.708 |
| consolidated_alerts | True | SUSPICIOUS | REPORT_ONLY | True | 54.451 |

All six candidate outputs passed the existing structured/fact checks; four of six matched reference verdict labels. That is not four correct security explanations. Maximum prompt: 988 tokens; maximum output: 177; full prompt plus reserved output fit and no truncation was reported. The first 28.161-second schema probe reused a warm prompt cache, so latency is not a controlled speed comparison.

## Remaining failures

- The compliant approved case was labelled Suspicious and described as potential compromise.
- The single-root boundary was labelled Benign, and its reason copied formatting instructions rather than explaining evidence.
- Unapproved and out-of-window cases claimed account existence was detected; failed-password records do not establish that.
- Several recommendations were action labels instead of useful investigation guidance.
- Existing regex prose guards did not reject every unsupported explanation. Structured fact acceptance must not be presented as verified prose or judgment.

Missing-evidence and malformed-output safety checks passed without model calls. No candidate output requested block approval, so this evaluation does not provide a new opportunity for a live block.

## Conclusion

Prompt clarity alone did not resolve the failure. Schema dependencies eliminated the observed verdict/action contradiction in this small sample, but did not repair reasoning or prose reliability. Do not activate this candidate as a model-quality fix or force a block recommendation. Keep the original live assessment outcomes unchanged. Any production schema strengthening should be a separately reviewed implementation with tests covering branch compatibility, output accounting and unchanged fact/approval/rollback checks. Further model comparison should use this same held-out fixture set and independent prose review.

Detailed prompts, raw responses, transport schemas, hashes and receipts remain in the ignored local verification directory. The existing active prompt and response policy were not modified by this diagnosis.
