# Windows Ollama cloud compatibility check

Tested 2026-11-05 (America/Vancouver) with the existing signed-in Windows Ollama account. The account API reported the `free` plan. No account identifiers or credentials are recorded here.

## Actual result

- Registered `gemma4:cloud`: a 312-byte routing configuration with no model-weight layers, rather than a local 32B model download.
- Sent one synthetic-only `/api/chat` request through the existing WSL-to-Windows-loopback transport, using the shared inference lock.
- Requested a JSON schema containing a constant synthetic marker, context 8,192, output budget 64, nonstreaming output, and a 60-second request deadline.
- Ollama rejected the request with **HTTP 402** after **0.286 seconds**, requiring usage credits or a subscription. This is rejection latency, not inference latency.
- No generated response, token counts, model identity response or security judgment was available to validate. Schema support, inference latency, memory consumption during inference and the six-scenario quality suite remain **untested**.

No billing change or real incident upload was made. This historical probe did not establish cloud compatibility or activate a cloud profile.

## Additional compatibility gate

[Ollama's structured-output documentation](https://docs.ollama.com/capabilities/structured-outputs) states that its cloud does not currently support structured outputs. The billing rejection occurred before a useful schema compatibility result, so it does not verify or disprove that limitation. Funding the account would not establish project compatibility.

Before any cloud deployment, independently verify schema support, trusted configured/returned model identity, complete evidence and output budgets, serialized bounded requests, Python fact and coverage validation, and the deterministic synthetic and boundary scenarios. Do not remove the schema or weaken validators merely to obtain a response. Actual incident evidence requires explicit authorization before leaving the laptop. Any paid usage requires separate operator authorization.

Detailed account/probe receipts remain local-only and are excluded from publication. Do not assume a later account has free usage or the same service capabilities; reverify current limits before another test.
