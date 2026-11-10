# macOS / UTM setup and readiness checkpoints

Follow this guide on a fresh lab in order. Run **Mac** commands from the cloned repository root, and **guest** commands from the named VM's console. This guide prepares the existing fixed implementation; it does not execute any setup, traffic or firewall action merely by being read.

The repository uses macOS UTM helpers, local Ollama and Ubuntu UFW. It has no Windows profile, arbitrary-hypervisor adapter or automatic VM installer. Offline tests can pass before any guest exists; live reproduction additionally requires every checkpoint below.

## 1. Prepare the Mac and obtain the source

Install [UTM](https://mac.getutm.app/) at `/Applications/UTM.app`, Python 3.12+ and [Ollama for macOS](https://ollama.com/download/mac). Use the QEMU backend for the Linux guests because the transport needs guest-agent execution and file transfer. Prefer guest images matching the Mac CPU architecture: ARM64 on Apple Silicon, x86-64 on Intel. Match available host memory to three guests plus inference; this repository does not qualify a universal RAM minimum.

On the Mac:

```sh
git clone https://github.com/mashaojin/soar-investigation-macOS.git
cd soar-investigation-macOS
python3 --version
ssh -V
/Applications/UTM.app/Contents/MacOS/utmctl list
python3 -m unittest discover -s tests -q
```

A private repository requires your GitHub account to have access. Existing local checkouts may still be called `soc-pipeline`; keep their local directory if configuration contains absolute paths. All commands in this guide assume the terminal is in that checkout's root.

**Checkpoint:** Python is 3.12+, the offline tests pass, UTM is installed at the expected path and `utmctl list` works. No actual guest test has run yet.

## 2. Create the guests and match the network

Create three independent Linux guests. On Apple Silicon, obtain the appropriate official ARM64 Ubuntu/Kali images; do not assume an x86 VirtualBox appliance is interchangeable with a UTM ARM guest. The original lab uses these defaults:

| UTM name | OS | Guest user | Address |
| --- | --- | --- | --- |
| `Victim` | Ubuntu | `victim` | `192.168.64.6/24` |
| `Kali Linux` | Kali Linux | `kali` | `192.168.64.4/24` |
| `Trust-Client` | Ubuntu | `trust-client` | `192.168.64.8/24` |

Use UTM **macOS Shared Network**, with host/guest isolation disabled, so the guests can reach one another and the Mac. Separate emulated VLANs do not provide the same topology. See [UTM network modes](https://docs.getutm.app/settings-qemu/devices/network/network/).

Use the guests' network settings to assign stable, unused addresses on your shared subnet. Inspect the actual UTM network for its prefix and gateway. The default subnet is `192.168.64.0/24`, with `192.168.64.1` as the Mac management source. Ubuntu Desktop/Kali can use their NetworkManager IPv4 settings; Ubuntu Server uses its existing Netplan interface configuration. Preserve the correct interface name, set the subnet prefix and actual gateway/DNS, and avoid competing DHCP/duplicate static assignments. Perform initial changes from the guest console so a bad route does not strand an SSH session.

For alternate names or addresses, create the topology on the Mac from the checkout:

```sh
cp -n config/topology.example.json topology.local.json
```

Edit `topology.local.json` to match the three UTM names, guest usernames and IPv4 addresses. Use plain IPv4 addresses without prefixes. Set `management_ip` to the Mac source confirmed by the [Victim SSH check](#4-establish-verified-mac-to-victim-ssh). All four addresses must be distinct. Use the default values in command examples below only if they match your setup. Substitute your configured addresses, usernames and UTM names wherever they appear.

With a local topology present, its identities take precedence over the SSH target and IP filters in the collector config and the victim and client addresses in the response policy. Existing additional protected IPs still apply. The policy still controls response mode, approval and duration. To move an existing lab, finish any pending live response and confirm rollback, stop the monitor and dashboard, then update the file. Re-establish SSH trust, restage both clients, create fresh plans for the new IPs and restart both services. A new SSH target gets a separate EVE cursor. Review the initial baseline before running traffic.

On **each guest**, inspect:

```sh
hostname
ip -4 -br address
ip route
date -u
```

On **each client**:

```sh
ip -4 route get 192.168.64.6
```

The route's source must match the configured IP for each client. Compare host/guest UTC clocks and correct time synchronization before creating plans. The test-plan form shows the browser timezone and stores UTC; incident labels/Telegram timestamps use `America/Vancouver`.

**Checkpoint:** `utmctl list` on the Mac shows all three exact names, guest addresses/routes are correct and clocks agree. A guessed IP is not readiness.

## 3. Prepare Victim services and the SSH sensor

### Install the guest services — Victim

On the fresh Ubuntu Victim:

```sh
sudo apt update
sudo apt install python3 openssh-server suricata ufw qemu-guest-agent acl jq
sudo systemctl enable --now ssh
sudo systemctl start qemu-guest-agent
sudo suricata --build-info
```

Use a supported Suricata package with the configuration-test and Unix command-socket functionality used by this lab. The official [Suricata quickstart](https://docs.suricata.io/en/latest/quickstart.html) documents the stable OISF PPA when an appropriate distribution package is unavailable. Source builds with different binary/config paths require code review; the fixed rule editor expects `/usr/bin/suricata`, `/usr/bin/suricatasc` and `/etc/suricata/suricata.yaml`.

### Prepare deliberately failed password tests — Victim

The helper needs password authentication to reach the SSH journal. Review the effective configuration:

```sh
sudo sshd -T | grep -E 'passwordauthentication|kbdinteractiveauthentication|permitrootlogin'
```

For this isolated lab, configure password authentication in an early-loaded Ubuntu drop-in, retaining public-key administration and keeping root login disabled:

```sh
sudoedit /etc/ssh/sshd_config.d/00-soar-lab.conf
```

Enter:

```text
PasswordAuthentication yes
KbdInteractiveAuthentication no
PermitRootLogin no
```

Do not assume a later drop-in overrides an earlier value; verify with `sshd -T`. Check and reload after editing:

```sh
sudo sshd -t
sudo systemctl reload ssh
```

For a real permitted-account test, create `soc_test` if absent:

```sh
sudo adduser soc_test
```

Choose its password locally and keep it different from the helper's deliberately invalid test value. The tests authorize failures, not successful access. Do not create an account named `soc_rehearsal_invalid`; the unapproved helper uses that invalid username. Root stays outside the plan and root login remains disabled. Actual journal evidence determines what was observed.

### Load the fixed SSH rule — Victim

Determine the interface carrying the configured Victim IP with `ip -4 -br address`. The examples below use `enp0s1`; replace the interface name if yours differs.

Create the rule from the repository's `rules/ssh_bruteforce.rules`. On Victim, the equivalent content is:

```sh
sudo install -d -m 0755 /etc/suricata/rules
sudo tee /etc/suricata/rules/ssh_bruteforce.rules >/dev/null <<'RULE'
alert tcp any any -> any 22 (msg:"ET SCAN Potential SSH Brute Force Attack"; flow:to_server; flags:S; threshold: type both, track by_src, count 5, seconds 30; classtype:attempted-admin; sid:9001001; rev:1;)
RULE
sudo chmod 0644 /etc/suricata/rules/ssh_bruteforce.rules
```

Back up the existing file once, then edit it on **Victim**:

```sh
sudo cp -n /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.before-soar-lab
sudoedit /etc/suricata/suricata.yaml
```

In this fresh, dedicated lab configuration, make the existing relevant sections agree with:

```yaml
default-log-dir: /var/log/suricata
default-rule-path: /etc/suricata/rules
rule-files:
  - ssh_bruteforce.rules

af-packet:
  - interface: enp0s1
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    tpacket-v3: yes

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert

unix-command:
  enabled: yes
```

These are sections to edit/merge, **not a complete replacement YAML file**. Do not add duplicate top-level keys. Preserve other required settings and set the log directory to `/var/log/suricata`. For the optional editor, include exactly one `  - ssh_bruteforce.rules` entry: its candidate validator replaces that fixed reference while testing the full configuration.

Inspect `sudo systemctl cat suricata` and any package startup defaults so the running service actually uses this YAML/interface; a service-level interface argument can override the YAML capture interface.

```sh
sudo install -d -m 0755 /var/log/suricata
sudo suricata -T --init-errors-fatal -c /etc/suricata/suricata.yaml -l /var/log/suricata
sudo systemctl enable suricata
sudo systemctl restart suricata
systemctl is-active ssh suricata
sudo suricatasc -c ruleset-stats
sudo test -f /var/log/suricata/eve.json
```

**Checkpoint:** the configuration test succeeds, both services are active, the command socket answers and EVE exists. A SYN-threshold alert is evidence to investigate, not a count of failed passwords. Do not run an attack simply to skip the remaining readiness steps.

### Allow read-only evidence access — Victim

The Mac collector logs in as `victim`; it does not run journal commands through unrestricted sudo. Grant the required local journal/log reading and verify it after a fresh login:

```sh
sudo usermod -aG systemd-journal victim
sudo setfacl -m u:victim:rx /var/log/suricata
sudo setfacl -m d:u:victim:r-x /var/log/suricata
sudo setfacl -m u:victim:r-- /var/log/suricata/eve.json
```

The directory default ACL gives newly created logs a read-access entry; inspect effective permissions after your log-rotation policy runs. Rotation can still require operator recovery, and permissions alone do not establish complete retention. Log out/in after group membership changes. Keep root-origin SSH records available before the first timed plan; the subsequent management login provides a normal prior service record.

### Prepare UFW — Victim

Review existing rules first. On the fresh lab, allow SSH **before** enabling UFW:

```sh
sudo ufw allow 22/tcp
sudo ufw enable
sudo ufw status numbered
```

**Checkpoint:** UFW is active and ordinary SSH is reachable. Existing source-specific rules for either configured client must be reviewed before a live test because the guard refuses ambiguous starting state. These steps do not install any temporary response deny.

## 4. Establish verified Mac-to-Victim SSH

On the **Victim console**, obtain its host-key fingerprint:

```sh
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

On the **Mac**, create a dedicated key if you do not already have an appropriate one. Do not overwrite an existing key at this path:

```sh
ssh-keygen -t ed25519 -f ~/.ssh/soar-lab-ed25519 -C soar-lab-management
ssh-add ~/.ssh/soar-lab-ed25519
```

Copy the public key using the initially configured `victim` password. Compare the displayed host fingerprint with the console before accepting the first connection:

```sh
cat ~/.ssh/soar-lab-ed25519.pub | ssh -o StrictHostKeyChecking=ask victim@192.168.64.6 'umask 077; mkdir -p ~/.ssh; cat >> ~/.ssh/authorized_keys; chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys'
```

Add or merge this matching host entry in your own `~/.ssh/config` so the pipeline's ordinary `ssh victim@192.168.64.6` finds the dedicated key:

```sshconfig
Host 192.168.64.6
    User victim
    IdentityFile ~/.ssh/soar-lab-ed25519
    IdentitiesOnly yes
    StrictHostKeyChecking yes
```

From a **new Mac connection**, verify noninteractive evidence access and the observed management source:

```sh
ssh -o BatchMode=yes victim@192.168.64.6 'id; printf "%s\n" "$SSH_CONNECTION"; test -r /var/log/suricata/eve.json; journalctl -u ssh.service -n 3 --no-pager -o json --output-fields=__REALTIME_TIMESTAMP,MESSAGE,_UID'
```

**Checkpoint:** there is no password/host-key prompt, the first field of `SSH_CONNECTION` matches `management_ip` and its last two fields match the Victim IP and port 22, EVE is readable and the journal contains readable root-origin records (`_UID: "0"`). A command returning no rows is not successful coverage. Start a fresh session after changing groups; a cached SSH master may retain old group membership. If necessary, stop the lab's old SSH master deliberately and reconnect before proceeding.

Establish the same verified Victim host-key trust from each **client VM** before using its demo helper. On each client, compare the prompt with Victim's console fingerprint:

```sh
ssh -o StrictHostKeyChecking=ask -o NumberOfPasswordPrompts=0 victim@192.168.64.6 true
```

With no client administration key configured, authentication may end in Permission denied; this step establishes host identity rather than successful access. The demo helper requires the verified key in the invoking guest account’s known-hosts file.

## 5. Verify UTM guest execution and stage clients

On both **Kali** and **Trust-Client**, install the needed local tools and start the agent:

```sh
sudo apt update
sudo apt install python3 openssh-client iproute2 netcat-openbsd qemu-guest-agent
sudo systemctl start qemu-guest-agent
systemctl is-active qemu-guest-agent
mkdir -p ~/soc-demo
```

UTM documents Linux agent installation in [guest support](https://docs.getutm.app/guest-support/linux/). Ensure the QEMU guest-agent channel is present in each VM. A service that cannot start without its channel is not a reason to skip the agent check.

The current UTM probes write beneath `/run`, and the live guard requires root. Verify the agent execution identity on the **Mac**; this writes only a readiness receipt on the selected guest:

```sh
UTM=/Applications/UTM.app/Contents/MacOS/utmctl
"$UTM" exec Victim --cmd /usr/bin/python3 -c 'import json,os; from pathlib import Path; Path("/tmp/soar-agent-check.json").write_text(json.dumps({"uid":os.geteuid()}))'
"$UTM" file pull Victim /tmp/soar-agent-check.json
```

Read `{"uid": 0}` from the pulled receipt. Repeat with the configured Kali and trusted-client UTM names. Quote VM names that contain spaces. UTM execution may return before the guest finishes: if the receipt is not yet available, wait briefly and read it again rather than repeatedly dispatching commands or assuming empty stdout means success. This is an explicit root-capable lab transport; do not interpret the unprivileged `victim` SSH login as equivalent permission.

On the **Mac**, stage the client helper:

```sh
python3 stage_demo_clients.py
```

It copies the client script, topology module and effective topology into `/home/<configured-user>/soc-demo/` on each client, then pulls each file back and verifies its bytes. The staging step generates no test traffic.

On the **named client**:

```sh
# Kali
python3 ~/soc-demo/ssh_demo_client.py --mode unapproved --preflight
```

```sh
# Trust-Client
python3 ~/soc-demo/ssh_demo_client.py --mode approved --preflight
```

**Checkpoint:** staging reports `verified: true`, preflights report the correct route source and `attack_executed: false`, and each client has trusted the Victim key. Do not run the obsolete `/tmp/soar-ssh-demo.py` path or the retired manual live-pilot workflow.

## 6. Initialize local state, Ollama and the dashboard

On the **Mac**, in the checkout:

```sh
python3 configure_local.py
ollama pull gemma4:e4b
ollama list
curl --fail http://127.0.0.1:11434/api/tags
```

Start the Ollama app before checking its API, or intentionally run one `ollama serve` instance. `gemma4:e4b` must appear. The code validates model identity for each request. An eligible Ollama SSH report can include local ATT&CK context in its primary assessment request. See the [retrieval setup and evaluation](../README.md#mitre-attck-context-for-ssh). See the [official local-model quickstart](https://docs.ollama.com/quickstart).

Initialization creates absent local JSON, an empty plan registry and a new prompt store seeded from `prompts/current.txt`. Existing state is preserved. Check response mode without printing credentials:

```sh
python3 - <<'PY'
import json
from pathlib import Path
policy=json.loads(Path('response.local.json').read_text())
print('Response mode:',policy['mode'])
print('Exclusive polling confirmed:',policy['exclusive_polling_confirmed'])
PY
```

A new installation should report dry run and unconfirmed polling. Use two **Mac terminals**, both in the checkout:

```sh
# Terminal 1
python3 dashboard.py
```

```sh
# Terminal 2
python3 monitor.py --config live.ssh.local.json --runtime runtime.ssh.live.local.json --db ssh-live.sqlite3
```

Open `http://127.0.0.1:8765/`. Verify the monitor heartbeat and successful collection batches. The first baseline intentionally starts at the end of EVE; establish it **before** running the manual scenarios. This command performs AI assessments when windows are ready; without `--telegram` it does not run Telegram polling or dispatch live responses.

**Checkpoint:** the page and Settings load, Monitor running is fresh, collection succeeds and the exact local model is available. The dashboard server and monitor need their own running terminals. Closing a foreground terminal stops its service.

## 7. Configure Telegram and complete a dry-run rehearsal

Create your own bot with BotFather and start its private chat. On the **Mac**:

```sh
cp .env.example .env
chmod 600 .env
```

Edit `.env` locally with your bot token and positive private chat ID; set the user ID to that same private-chat owner's ID. Never send a token to a collaborator or commit the file. Only source a file you created and reviewed:

```sh
set -a
source .env
set +a
python3 response.py --check
```

`--check` verifies the bot/chat/webhook prerequisites without sending messages or polling. A missing/incorrect private chat must be fixed locally before continuing. If you need to identify the chat ID, stop all bot consumers, send `/start` yourself, and inspect the Telegram Bot API `getUpdates` response locally; do not publish its messages or token-bearing URL.

Stop the monitor with Ctrl-C and wait for shutdown. Confirm no old Hermes loop, standalone pilot or other consumer polls this bot. In `response.local.json`, retain `mode: dry_run` and set `exclusive_polling_confirmed: true`. Then in the **monitor terminal**, with credentials exported:

```sh
python3 monitor.py --config live.ssh.local.json --runtime runtime.ssh.live.local.json --db ssh-live.sqlite3 --telegram
```

Follow the README's [three manual scenarios](../README.md#three-manual-scenarios), one at a time. Create fresh plans in the dashboard before their start and verify the source, account, limit and timezone. Inspect the evidence, AI report, Telegram result and dashboard response record at each step. YES in dry run records a simulation only. Report-only or manual-review outcomes are legitimate when supported; they are not permission to weaken validators.

**Checkpoint:** Telegram delivery and the authorized decision path are working with no real block. Merely opening the bot chat or observing an AI label does not qualify live response.

## 8. Enable and verify live response

For a plain-text SSH advisory, record Suspicious in the dashboard or Telegram. Eligible live incidents then get a separate Telegram firewall approval.

Do this only after the dry-run checks and deliberate review of `live_response.py` and `live_lab_guard.py`. Victim must have active UFW, a working root guest-agent path, a functioning systemd timer and no ambiguous existing source-specific rule. Keep guest consoles available and do not suspend/reboot Victim during a block.

Wait for previous work to finish, stop the monitor, and review the effective scope from the topology and `response.local.json`. Only the configured clients may be blocked, only to Victim TCP/22, for 60 seconds after explicit approval. The worker verifies the management source using a fresh, host-key-verified SSH session before dispatch. Activate only new incidents using a current UTC timestamp:

```sh
python3 - <<'PY'
from datetime import datetime,timezone
from pathlib import Path
import json
path=Path('response.local.json')
policy=json.loads(path.read_text())
policy.update(mode='live',duration_seconds=60,live_enabled_after=datetime.now(timezone.utc).isoformat())
path.write_text(json.dumps(policy,indent=2)+'\n')
print('Live mode selected for new incidents after the recorded activation time.')
PY
```

Restart the same Telegram-enabled monitor with credentials exported. The dashboard and eligible requests must clearly identify **LIVE** mode. The live worker additionally requires a saved Suspicious review, fresh current-revision SSH evidence, observed-window coverage and no successful authentication. An approved plan without an observed account-scope violation is report-only under the live policy, even if some other finding concerns the model.

Run a **new** unapproved Kali scenario after activation and review the recorded evidence. Record **Suspicious** if it supports that conclusion. If a separate block request arrives, inspect its incident, source, target, duration and expiry. Before clicking YES, on **Kali** start an independent observation:

```sh
for i in $(seq 1 20); do date +%T; nc -nvz -w 2 192.168.64.6 22; sleep 3; done
```

Approve the exact **LIVE 60s block** request yourself. On the **Victim console**, inspect:

```sh
sudo ufw status numbered
```

The worker checks baseline source connectivity and dispatches once. Victim records state under `/run/soc-lab-tests/<run_id>/state.json`, arms and verifies its rollback timer, then inserts a deny tagged `soc-lab-<run_id>`. The deadline is about 60 seconds after arming; the actual deny interval may be slightly shorter because application happens afterward.

**Checkpoint:** new SSH connections from the source time out during the deny; protected management remains available; the tagged deny disappears; new source connections become reachable again; and the dashboard/Telegram records completed rollback. A general SSH ALLOW line may remain throughout because it is lower priority than the temporary source deny.

If the model requests review or policy rejects the block, inspect that outcome instead of claiming enforcement passed. If execution is uncertain, read the recorded run/receipt and timer state before any recovery; do not redispatch apply or flush unrelated rules. The timer runs on Victim even if the Mac application stops, but reboot/suspend can interrupt the transient lab mechanism.

To return to dry run, wait for completion, stop the monitor, set `mode` back to `dry_run`, and restart. Do not use the old `live_lab.py prepare/check/run` CLI for the continuous workflow; `live_lab.py` remains only a transport dependency for the live worker's source probes.

## 9. Optional dashboard rule editor and prompt experiments

The sensor can run the three scenarios without a dashboard rule editor. To enable editing, explicitly review `install_rule_editor.py` and `soc_rule_helper.py`, then run on the **Mac**:

```sh
python3 install_rule_editor.py
```

This installs a root-owned fixed helper on Victim through the verified guest agent and a narrowly scoped sudoers entry for that helper. It writes a local verification receipt after an independent SSH read. Do not copy another installation's `rule-editor-enabled.json` to claim provisioning succeeded.

On the dashboard choose **Settings → Suricata rule → Read from Victim**. Edit only the supported message/threshold/revision fields, validate, review the diff, and explicitly apply. Check the returned activation state. Unknown state requires reading Victim status before retrying. The YAML must keep the exact fixed rule reference and a working Unix command socket from step 3.

**Settings → AI prompt** supports save, same-evidence comparison and explicit activation. A saved version is not active until selected and activated. Comparisons call the model but send no Telegram messages or firewall commands. **Settings → AI model selection** configures Ollama or Gemini API and displays read-only pipeline limits. See [Gemini setup](GEMINI_PROVIDER.md). Changing a prompt on saved evidence does not test a new network rule on traffic that was never captured.

## Completion checklist

- [ ] Source tests pass and local files contain only this installation's identities.
- [ ] Guest names, addresses, routes and UTC clocks match the intended lab.
- [ ] Victim SSH, EVE capture, journal reading and source-key trust are verified.
- [ ] UTM execution/file receipts and required root identity are verified.
- [ ] Both client preflights pass without generating attempts.
- [ ] Dashboard and one continuous monitor run separately.
- [ ] Telegram uses one private authorized operator and one poller.
- [ ] All three dry-run scenario outcomes are inspected from actual evidence.
- [ ] Optional live response has separately verified deny, management access, timer, removal and restored source connectivity.
- [ ] Prompt/model limitations and rejected assessments remain documented rather than bypassed.
