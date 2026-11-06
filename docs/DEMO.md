# Three-scenario manual demonstration

Start from a healthy lab, active collector, Ollama and one Telegram-enabled monitor. Keep the monitor running for all scenarios. Check the dashboard response mode: dry run is the initial default; live mode performs an actual approved temporary block.

For Windows guest preparation, profile-selected client staging and current verification limits, use [Windows setup](WINDOWS.md). The Mac commands below retain their UTM defaults.

## Prepare clients

Create `~/soc-demo` in both client VMs, then run on the Mac:

```sh
python3 stage_demo_clients.py
```

This copies and verifies `ssh_demo_client.py`; it generates no traffic. Alternatively copy this file manually to `~/soc-demo/ssh_demo_client.py` on each client.

On Trust-Client:

```sh
python3 ~/soc-demo/ssh_demo_client.py --mode approved --preflight
```

On Kali:

```sh
python3 ~/soc-demo/ssh_demo_client.py --mode unapproved --preflight
```

Check that source addresses are `.8` and `.4`. Use the bounded demo only against your own victim lab.

## 1. Approved test

In the dashboard, select **New test plan**. Enter source `192.168.64.8`, target `192.168.64.6`, allowed account `soc_test`, attempt limit `10`, your operator name and a fresh future window lasting 3–5 minutes. Select **Validate**, inspect the scope and timezone, then **Approve plan**.

During the approved window, run once on Trust-Client:

```sh
python3 ~/soc-demo/ssh_demo_client.py --mode approved --execute
```

Expected evidence: six bounded attempts against `soc_test`, subject to actual SSH protection behavior. A Benign assessment is the intended demonstration when retained observations support the approved scope. Gemma may request review when evidence is incomplete or ambiguous. An approved plan is not a forced Benign verdict.

## 2. Unapproved activity

Ensure there is no matching approved plan for Kali `.4`. Run once on Kali:

```sh
python3 ~/soc-demo/ssh_demo_client.py --mode unapproved --execute
```

The model weighs observed failures, lack of authorization and other retained evidence. The intended demonstration is Suspicious with a block-approval recommendation, but no fixed failure count forces that result. If a valid eligible request is issued, Telegram offers approval or denial. Check its incident number, timestamp, target, duration and dry-run/live label before responding.

In live mode, from Kali start this connectivity observation around approval time:

```sh
for i in $(seq 1 20); do date +%T; nc -nvz -w 2 192.168.64.6 22; sleep 3; done
```

After an approved live action, new SSH connections should time out during the block and become reachable after rollback. The victim's broad SSH ALLOW rule can remain present: the temporary source-specific deny takes precedence while installed and is removed afterward. Verify the dashboard response result and victim firewall state as well as the client observation.

## 3. Root attempt during an approved test

Create and approve a new nonoverlapping plan for `.8` that permits only `soc_test`. During the window run once on Trust-Client:

```sh
python3 ~/soc-demo/ssh_demo_client.py --mode scope-violation --execute
```

The helper attempts `root` once and `soc_test` five times. The journal must actually contain the root attempt for that fact to reach Gemma. A scope violation is an observed fact; the AI explains its significance. Eligible suspicious scope violations may produce a separate block request. Such a source-IP block also interrupts permitted SSH testing from that source during its duration.

## Timing and interpretation

Unapproved activity uses a fixed two-minute correlation window, up to one minute of pre-alert evidence and a 30-second arrival allowance. Approved activity uses the full approved plan window plus the arrival allowance. Collection catch-up and model latency add further delay. Closely related attempts in one scope are consolidated; do not expect one incident for every helper invocation. Authorization boundaries prevent planned and unplanned windows from being intentionally merged.

Each execution makes six attempts in two bursts separated by 12 seconds. Permission-denied client output does not establish six failed-password journal records: OpenSSH may reject a connection early. Failed logins do not prove compromise.

If an incident requires review, inspect its evidence on the dashboard and choose Benign, Suspicious or Need more evidence. Telegram review buttons record only a human conclusion. They are distinct from firewall-approval buttons. Model reasoning and human review remain separately visible.

For a repeat demonstration, create fresh plans and wait for the earlier incident/block to finish. Do not reset cursors, clear incident history or expand a plan to excuse a root attempt.
