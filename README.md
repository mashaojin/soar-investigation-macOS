# SOAR investigation dashboard

An educational SSH investigation and response lab: **Suricata → Python evidence collection → local Gemma assessment → Telegram operator decision → optional temporary firewall response**.

The dashboard shows incidents, evidence, AI assessments, human reviews, response progress and approved test plans. Settings provides a prompt editor, saved-evidence comparisons, a constrained Suricata rule editor and read-only pipeline configuration.

![SOAR dashboard showing incident history, severity, investigation stages and a completed temporary SSH block](docs/images/dashboard-overview.jpg)

*Dashboard overview from a recorded lab rehearsal: incident history, AI verdict, stage progress and verified response completion.*

## Dashboard walkthrough

<details>
<summary>Define the approved test scope</summary>

![Test-plan editor showing source and target IPs, permitted account, attempt limit and start/end times](docs/images/test-plan-editor.jpg)

*The operator defines the scope before validation and explicit approval. This screenshot is an unsaved example; no test plan was approved to create it.*

</details>

<details>
<summary>Inspect the AI assessment and response status</summary>

![Gemma explanation, recommended next step, evidence coverage and completed SSH response](docs/images/incident-assessment.jpg)

*Gemma's explanation and recommendation appear beside the recorded response status. Python validates the facts and independently enforces response approval.*

</details>

## Telegram notifications

| Temporary response and rollback | Manual-review notice |
| --- | --- |
| ![Telegram SSH response message with incident date and time and confirmed live rollback](docs/images/telegram-live-response.png) | ![Telegram manual-review notice with incident reference, date, time, reason and dashboard link](docs/images/telegram-manual-review.png) |

*Actual messages from recorded lab incidents, cropped to the relevant messages. The live-response example shows the completed state after the temporary deny was removed; its approval buttons are no longer displayed. The review notice explains why the saved incident needs operator attention.*

## What makes the assessment

Python continuously collects and correlates alerts, reads scoped SSH authentication records and checks the approved test-plan scope. Gemma chooses a verdict and recommended next step from those facts. Python validates the result and independently enforces response policy. The current version uses one direct Ollama request per assessment; Hermes and autonomous model tool use are not part of this final workflow.

Suspicious is an assessment, not proof of compromise. Missing evidence or an invalid model response goes to human review. Human conclusions remain separate from AI assessments; they do not authorize firewall changes.

## Lab and requirements

- Host: macOS with UTM, OpenSSH, Python 3.12+ and Ollama with `gemma4:e4b`.
- Victim: Ubuntu, `192.168.64.6`, SSH + Suricata + UFW.
- Attacker: Kali, `192.168.64.4`.
- Approved-test client: Ubuntu, `192.168.64.8`.
- Management source: `192.168.64.1`, protected from the response rule.

Python code uses the standard library; there is no pip install step. Offline tests also run on Linux. The live VM helpers intentionally target this topology and UTM VM names; changing JSON alone does not retarget the entire lab.

## Start

Run from this directory:

```sh
python3 configure_local.py
python3 dashboard.py
```

In another terminal, after reviewing the local configuration and starting the lab VMs and Ollama:

```sh
python3 monitor.py --config live.ssh.local.json --runtime runtime.ssh.live.local.json --db ssh-live.sqlite3
```

Open [the dashboard](http://127.0.0.1:8765/). The dashboard does not start the monitor. Stop either foreground process with Ctrl-C. The monitor remains running across incidents.

For Telegram, follow [setup](docs/SETUP.md), export the bot credentials, confirm exclusive bot polling, then add `--telegram` to the monitor command. New configuration defaults to **dry run**. Existing local configuration is preserved by setup; inspect the dashboard mode before approving a response.

## Documentation

- [Setup and configuration](docs/SETUP.md)
- [Three-scenario manual demonstration](docs/DEMO.md)
- [Architecture, files and decision boundaries](docs/ARCHITECTURE.md)
- [Settings, reviews and operations](docs/OPERATIONS.md)
- [Repository contents and publication checklist](docs/REPOSITORY.md)

## Verification

```sh
python3 -m unittest discover -s tests -q
node --check web/app.js
node --check web/experiments.js
```

The suite uses synthetic fixtures, isolated databases, mocked external calls and temporary localhost HTTP servers. It requires no VMs, Telegram credentials or running model and sends no real attacks or firewall commands. GitHub Actions runs the offline suite on Python 3.12.

Optional actual-model evaluation:

```sh
python3 verify_gemma.py
```

This calls local Ollama using three synthetic scenarios and writes an ignored verification receipt. Model classifications can vary; passing offline tests does not establish accuracy on all attacks or prove a fresh live rehearsal.

## Repository layout

```text
soc-pipeline/
├── README.md
├── configure_local.py       # Non-destructive local initialization
├── monitor.py               # Continuous collector, analyst and response orchestration
├── dashboard.py             # Loopback dashboard and protected APIs
├── *.py                     # Supporting pipeline and bounded lab helpers
├── config/                  # Public configuration examples
├── docs/                    # Current setup, architecture and demonstration guides
├── fixtures/                # Synthetic regression-test inputs
├── plans/                   # Local registry location (actual plans ignored)
├── prompts/                 # Exported current and built-in instructions
├── rules/                   # Example SSH Suricata rule
├── tests/                   # Offline regression tests
├── web/                     # Dashboard HTML, JavaScript and CSS
└── .github/workflows/       # Offline CI
```

Operational databases, actual approvals/test plans, credentials, machine-specific JSON, logs and generated results are excluded from Git. Historical development files are preserved in a separate local archive outside this folder. Use the published repository files, not the entire surrounding workspace, when sharing the project.
