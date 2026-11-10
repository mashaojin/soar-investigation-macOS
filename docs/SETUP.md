# Setup and configuration

For a fresh installation, follow the ordered [macOS / UTM guide](MACOS.md). This page is a configuration overview; the full guide supplies guest setup, sensor configuration, SSH access, readiness checks and live-response verification. The repository is now named `soar-investigation-macOS`; existing local `soc-pipeline` directories can remain in place.

## 1. Match the lab topology

The original UTM lab identities are the defaults. To use alternate VM names, accounts or IPv4 addresses, configure `topology.local.json` as described in the [macOS networking setup](MACOS.md#2-create-the-guests-and-match-the-network).

On the victim, SSH and Suricata must run, EVE JSON must be written to `/var/log/suricata/eve.json`, and the SSH rule with SID `9001001` must be included in the active Suricata configuration. `rules/ssh_bruteforce.rules` supplies the lab rule. Validate Suricata configuration before loading a rule. Its SYN threshold triggers collection; it does not decide whether passwords failed or whether activity is malicious.

The victim account needs read access to EVE and the root-origin `ssh.service` journal records used by `ssh_auth_reader.py` (for example, approved local journal-group membership). Establish host SSH keys and trust the victim's verified host key before using batch collection. Test read access directly; do not disable host-key checking.

For live enforcement, UFW must be active. The configured Mac management source and Victim address are protected. UTM guest-agent execution must work on all three VMs; the victim agent must support the existing root-level bounded helper operations. Keep the victim running during a live block so its scheduled rollback can execute. Provisioning guest agents and VM privileges is an explicit lab setup task; local initialization does not grant access or install software in a VM.

On the host, install Python 3.12+, Ollama and the base `gemma4:e4b` model. The code contacts Ollama on local port 11434. There are no Python package dependencies beyond the standard library.

## 2. Create private local files

From the repository root:

```sh
python3 configure_local.py
```

This copies absent JSON files from `config/`, creates an empty plan registry and initializes a new prompt store using `prompts/current.txt`. It preserves existing files, plans and active prompt selections. It does not contact VMs, Telegram or Ollama and makes no firewall changes.

| Local file | Purpose |
|---|---|
| `live.ssh.local.json` | EVE SSH source, filters and poll interval |
| `runtime.ssh.live.local.json` | Dashboard plan registry path and model identity |
| `response.local.json` | Response mode, source restrictions, duration and approval policy |
| `plans/dashboard-plans.json` | Actual operator-approved test plans |
| `lab-experiments.sqlite3` | Prompt versions, active prompt and comparisons |

These files are ignored by Git. Examples default to `dry_run`, and exclusive Telegram polling is initially unconfirmed. Existing users retain their existing mode; review it before a demonstration.

## 3. Start the dashboard and monitor

Use two terminals in the repository root:

```sh
python3 dashboard.py
```

```sh
python3 monitor.py --config live.ssh.local.json --runtime runtime.ssh.live.local.json --db ssh-live.sqlite3
```

Open `http://127.0.0.1:8765/`. Use the monitor heartbeat and collector output to verify monitoring; a working HTTP page alone proves neither collection nor AI availability. The first collection with `start_at: end` establishes a baseline and skips prior EVE history. Subsequent starts resume the stored cursor. Never delete the database as a routine restart procedure.

## 4. Enable Telegram

Create a bot and obtain your own private chat ID. Copy `.env.example` to `.env` and replace the placeholders. This file contains secrets and is ignored by Git. Export its values in the terminal that will run the monitor:

```sh
set -a
source .env
set +a
```

Stop every other process polling this bot, then set `exclusive_polling_confirmed` to `true` in `response.local.json`. Restart one monitor with the previous command plus `--telegram`. The configured private-chat owner is the only permitted operator. The dashboard does not poll the bot independently.

The credential loader supports environment variables and, for existing installations, a local legacy Python constants file identified by `credentials_source`; it reads constants without executing that file. Environment variables avoid including that legacy file in a new checkout.

## 5. Optional live mode and rule editor

Verify all three scenarios and dry-run decisions first. For a deliberate live rehearsal, set `mode` to `live`, keep `duration_seconds` at `60`, and set `live_enabled_after` to the current UTC ISO timestamp. Restart the monitor. Only new, eligible incidents after activation can lead to a live request. A suspicious model recommendation still requires an incident-bound Telegram approval; approving a test plan or human review does not grant this permission.

The rule editor is disabled until its fixed helper has been provisioned on the victim. Review `install_rule_editor.py` and `soc_rule_helper.py` before explicitly running the installer. It uses UTM guest execution to install a root-owned helper and narrowly scoped sudo entry, then verifies the installation over SSH. `rule-editor-enabled.json` is a local receipt, not a portable permission grant. Do not copy someone else's receipt to claim provisioning succeeded.

The implementation is a fixed educational lab. It is not a general production deployment or an automatic VM provisioning system.
