"""One-off LIVE lab pilot. Normal monitor/response.py remain dry-run-only."""
import argparse
from contextlib import closing
from datetime import datetime, timezone
import fcntl
import hashlib
import json
from pathlib import Path
import re
import secrets
import sqlite3
import subprocess
import sys
import time

from live import ssh_command
from response import canonical, prime_updates
from telegram_client import TelegramClient, bot_lock, load_credentials


HERE = Path(__file__).resolve().parent
DB = HERE / "live-lab.sqlite3"
UTM = "/Applications/UTM.app/Contents/MacOS/utmctl"


def connection():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    db.execute("""CREATE TABLE IF NOT EXISTS live_lab_tests (
        run_id TEXT PRIMARY KEY, plan TEXT NOT NULL, plan_hash TEXT NOT NULL,
        status TEXT NOT NULL, message_id INTEGER, created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL, bot_key TEXT NOT NULL, chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL, result TEXT)""")
    db.commit()
    return db


def live_plan(incident_id, snapshot=None):
    plan = dict(mode="live_lab_test", source="192.168.64.4", destination="192.168.64.6",
                port=22, protocol="tcp", duration_seconds=60, incident_id=incident_id,
                management_ip="192.168.64.1", rollback="Ubuntu systemd timer armed before apply")
    if snapshot is not None:
        plan['assessment_snapshot'] = snapshot
    return plan


def current_rehearsal_incident(incident_id, *, now=None):
    """Require a fresh, complete current-revision lab assessment, never an old pilot."""
    if not re.fullmatch(r'[0-9a-f]{64}', incident_id):
        raise ValueError('Expected the full current incident ID')
    with closing(sqlite3.connect(HERE / 'ssh-live.sqlite3')) as db:
        row = db.execute('''SELECT i.evidence,i.revision,a.report,a.metadata
            FROM incidents i JOIN analyses a ON a.incident_id=i.incident_id AND a.revision=i.revision
            WHERE i.incident_id=? AND a.status='complete' ''', (incident_id,)).fetchone()
        baseline = db.execute("SELECT recorded_at FROM remote_audit WHERE kind='operator_rebaseline_20261103' ORDER BY recorded_at DESC LIMIT 1").fetchone()
    if not row or not baseline:
        raise ValueError('A complete assessment after the fresh baseline is required')
    evidence, revision, report, metadata = json.loads(row[0]), row[1], json.loads(row[2]), json.loads(row[3])
    start = datetime.fromisoformat(evidence['window_start'].replace('Z', '+00:00'))
    baseline_time = datetime.fromisoformat(baseline[0]).replace(tzinfo=timezone.utc)
    current_time = datetime.now(timezone.utc) if now is None else now
    if start <= baseline_time or not 0 <= (current_time-start).total_seconds() <= 1800:
        raise ValueError('Incident must follow the approved baseline and be under 30 minutes old')
    if (evidence.get('source_ip'), evidence.get('destination_ip'), evidence.get('destination_port'), evidence.get('signature_id')) != ('192.168.64.4', '192.168.64.6', 22, 9001001):
        raise ValueError('Incident is outside the fixed Kali SSH scope')
    investigation = metadata.get('investigation', {})
    auth = investigation.get('authentication', {})
    checks = auth.get('coverage_checks', {})
    from lab_config import MAC
    if (metadata.get('engine') != 'ollama_direct' or metadata.get('model') != MAC['ollama']['model']
            or investigation.get('origin') != 'live_read_only'
            or report.get('verdict') != 'SUSPICIOUS' or report.get('coverage') != 'observed_window'
            or auth.get('coverage') != 'observed_window' or auth.get('limited') is not False
            or any(checks.get(k) is not True for k in ('query_not_limited','retained_entry_before_start','root_service_records','window_elapsed'))
            or auth.get('source_ip') != '192.168.64.4' or auth.get('target_ip') != '192.168.64.6'
            or type(auth.get('failed_password_count')) is not int or auth['failed_password_count'] < 6
            or auth.get('successful_login_count') != 0
            or investigation.get('plan_evidence', {}).get('plan') is not None):
        raise ValueError('Fresh unapproved activity requires six verified failures, no successes, complete coverage and accepted Gemma assessment')
    snapshot = dict(revision=revision, hash=digest(dict(evidence=evidence,report=report,metadata=metadata)))
    return evidence, report, snapshot


def digest(plan):
    return hashlib.sha256(canonical(plan).encode()).hexdigest()


def victim_read(code):
    config = json.loads((HERE / "live.local.json").read_text())
    result = subprocess.run(ssh_command(config, code), capture_output=True, text=True,
                            timeout=15, check=True)
    return result.stdout


def kali_probe(probe_id):
    return client_probe(probe_id,'192.168.64.4')


def client_probe(probe_id,source):
    machines={'192.168.64.4':'Kali Linux','192.168.64.8':'Trust-Client'}
    if source not in machines: raise ValueError('Unsupported lab client')
    machine=machines[source]
    if not re.fullmatch(r"[0-9a-f]{24}", probe_id):
        raise ValueError("Invalid probe ID")
    path = "/run/soc-lab-probes/" + probe_id + ".json"
    code = """import json,pathlib,socket,time
p=pathlib.Path('/run/soc-lab-probes');p.mkdir(mode=0o700,exist_ok=True)
s=socket.socket();s.settimeout(3)
result={'source':%r,'destination':'192.168.64.6','port':22}
try:
 s.connect(('192.168.64.6',22));result.update(reachable=True,actual_source=s.getsockname()[0])
except OSError as e:
 result.update(reachable=False,error=type(e).__name__)
finally:
 s.close()
(p/'%s.json').write_text(json.dumps(result))
""" % (source,probe_id)
    subprocess.run([UTM, "exec", machine, "--cmd", "/usr/bin/python3", "-c", code],
                   capture_output=True, timeout=10, check=True)
    # UTM exec can return before guest completion. Read a separate guest receipt.
    for _ in range(12):
        result = subprocess.run([UTM, "file", "pull", machine, path],
                                capture_output=True, text=True, timeout=5)
        try:
            payload = json.loads(result.stdout)
            if "reachable" in payload:
                return payload
        except ValueError:
            pass
        time.sleep(0.5)
    raise RuntimeError("Client probe receipt unavailable; do not infer connectivity from UTM stdout")


def prepare(client, identity, incident_id=None):
    with closing(connection()) as db, db:
        prior = db.execute("SELECT run_id,status FROM live_lab_tests ORDER BY created_at DESC LIMIT 1").fetchone()
        if prior:
            return dict(run_id=prior[0], status=prior[1], message="Existing test retained; no duplicate message sent")
    snapshot = None
    if incident_id is not None:
        evidence, report, snapshot = current_rehearsal_incident(incident_id)
        row = (incident_id, canonical(evidence), canonical(report))
    else:
      with closing(sqlite3.connect(HERE / "live.sqlite3")) as source:
        row = source.execute("""SELECT i.incident_id,i.evidence,a.report FROM incidents i
            JOIN analyses a ON a.incident_id=i.incident_id AND a.revision=i.revision
            WHERE a.status='complete' ORDER BY a.created_at DESC LIMIT 1""").fetchone()
    if row is None:
        raise ValueError("A verified lab incident is required")
    evidence = json.loads(row[1])
    if (evidence.get("source_ip"), evidence.get("destination_ip"), evidence.get("signature_id")) != (
            "192.168.64.4", "192.168.64.6", 9001001):
        raise ValueError("Incident is outside this fixed lab test scope")
    from incident_labels import attach as attach_label,header as incident_header
    with closing(sqlite3.connect(HERE / ("ssh-live.sqlite3" if incident_id else "live.sqlite3"))) as label_db:
        label_row=label_db.execute("SELECT revision FROM incidents WHERE incident_id=?",(row[0],)).fetchone()
        incident_label=attach_label(label_db,dict(incident_id=row[0],revision=label_row[0]))
    baseline = kali_probe(secrets.token_hex(12))
    if not baseline.get("reachable") or baseline.get("actual_source") != "192.168.64.4":
        raise RuntimeError("Kali must reach Ubuntu TCP/22 before the test")
    client.check()
    prime_updates(DB, client, identity)
    run_id, now = secrets.token_hex(12), int(time.time())
    plan = live_plan(row[0], snapshot)
    assessment_text = ''
    if snapshot is not None:
        assessment_text = ('Gemma assessment: SUSPICIOUS. Six or more verified failed logins; '
                           'no matching approved test plan; no successful login observed.\n'
                           'Bound assessment revision: ' + str(snapshot['revision']) + '\n')
    with closing(connection()) as db, db:
        db.execute("INSERT INTO live_lab_tests VALUES(?,?,?,'sending',NULL,?,?,?,?,?,?)",
                   (run_id, canonical(plan), digest(plan), now, now+600, identity["bot_key"],
                    identity["chat_id"], identity["user_id"], canonical(dict(baseline=baseline))))
    payload = {"chat_id": identity["chat_id"], "text":
        "LIVE LAB FIREWALL TEST — ACTUAL BLOCK\n"
        f"Test: {run_id}\n"+incident_header(incident_label)
        + assessment_text +
        "Block Kali 192.168.64.4 → Ubuntu 192.168.64.6 TCP/22 for 60 seconds.\n"
        "Ubuntu will arm its own rollback timer BEFORE adding the deny.\n"
        "Mac management access from 192.168.64.1 is outside this rule.\n"
        "This is a separate one-time live response using the incident already analyzed; "
        "the regular monitor remains dry-run-only.\n"
        "Tapping approval records permission; run the live helper's run command to apply it.\n"
        "Approval expires in 10 minutes. A VM reboot during the minute interrupts the transient timer; do not reboot during this test.",
        "reply_markup": {"inline_keyboard": [[
            {"text": "Approve LIVE 60s block", "callback_data": "soclive:a:"+run_id},
            {"text": "Deny", "callback_data": "soclive:d:"+run_id}]]}}
    try:
        sent = client.call("sendMessage", payload)
        if sent.get("chat", {}).get("id") != identity["chat_id"] or type(sent.get("message_id")) is not int:
            raise RuntimeError("Uncertain live approval delivery")
    except Exception:
        with closing(connection()) as db, db:
            db.execute("UPDATE live_lab_tests SET status='delivery_unknown' WHERE run_id=?", (run_id,))
        raise
    with closing(connection()) as db, db:
        db.execute("UPDATE live_lab_tests SET status='pending',message_id=? WHERE run_id=?", (sent["message_id"], run_id))
    return dict(run_id=run_id, status="pending", baseline=baseline, message_id=sent["message_id"])


def poll(client, identity):
    with closing(connection()) as db:
        offset = db.execute("SELECT next_update FROM telegram_offsets WHERE bot_key=?", (identity["bot_key"],)).fetchone()[0]
    updates = client.call("getUpdates", dict(offset=offset, timeout=0, limit=100,
                                             allowed_updates=["message", "callback_query"]))
    outcomes = []
    for update in updates:
        query = update.get("callback_query") or {}
        match = re.fullmatch(r"soclive:([ad]):([0-9a-f]{24})", query.get("data", ""))
        outcome = "ignored"
        with closing(connection()) as db, db:
            if match:
                decision, run_id = match.groups()
                row = db.execute("SELECT * FROM live_lab_tests WHERE run_id=?", (run_id,)).fetchone()
                message = query.get("message") or {}
                authorized = row and row["bot_key"] == identity["bot_key"] and row["chat_id"] == identity["chat_id"] and row["user_id"] == identity["user_id"] and query.get("from", {}).get("id") == row["user_id"] and not query.get("from", {}).get("is_bot") and message.get("chat", {}).get("id") == row["chat_id"] and message.get("chat", {}).get("type") == "private" and message.get("message_id") == row["message_id"]
                if authorized and row["status"] == "pending":
                    outcome = "expired" if int(time.time()) >= row["expires_at"] else "approved" if decision == "a" else "denied"
                    db.execute("UPDATE live_lab_tests SET status=? WHERE run_id=?", (outcome, run_id))
                else:
                    outcome = "rejected"
            db.execute("UPDATE telegram_offsets SET next_update=max(next_update,?) WHERE bot_key=?",
                       (update["update_id"]+1, identity["bot_key"]))
        if match:
            outcomes.append(outcome)
        if query.get("id"):
            try:
                client.call("answerCallbackQuery", dict(callback_query_id=query["id"], text="Live test decision recorded" if outcome in ("approved", "denied") else "Request not available"))
            except Exception:
                pass
    return outcomes


def read_state(run_id):
    return json.loads(victim_read("from pathlib import Path; print(Path(" + repr("/run/soc-lab-tests/"+run_id+"/state.json") + ").read_text())"))


def execute(client, identity):
    poll(client, identity)
    with closing(connection()) as db, db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT * FROM live_lab_tests ORDER BY created_at DESC LIMIT 1").fetchone()
        if not row or row["status"] != "approved":
            return dict(status=row["status"] if row else "missing", applied=False)
        plan = json.loads(row["plan"])
        snapshot = None
        if 'assessment_snapshot' in plan:
            _, _, snapshot = current_rehearsal_incident(plan['incident_id'])
        expected = live_plan(plan["incident_id"], snapshot)
        if (plan != expected or digest(plan) != row["plan_hash"] or int(time.time()) >= row["expires_at"]
                or row["bot_key"] != identity["bot_key"] or row["user_id"] != identity["user_id"]
                or row['chat_id'] != identity['chat_id']):
            raise RuntimeError("Live approval binding invalid or expired")
        db.execute("UPDATE live_lab_tests SET status='executing' WHERE run_id=?", (row["run_id"],))
    run_id = row["run_id"]
    result = json.loads(row["result"])
    result["pre_apply_probe"] = kali_probe(secrets.token_hex(12))
    if not result["pre_apply_probe"].get("reachable") or result['pre_apply_probe'].get('actual_source') != '192.168.64.4':
        raise RuntimeError("Pre-apply connectivity is already blocked; no rule added")
    if 'assessment_snapshot' in plan:
        _, _, fresh_snapshot = current_rehearsal_incident(plan['incident_id'])
        if fresh_snapshot != plan['assessment_snapshot'] or int(time.time()) >= row['expires_at']:
            raise RuntimeError('Assessment changed or approval expired before dispatch; no block added')
    source = (HERE / "live_lab_guard.py").read_text()
    # One dispatch only; an empty UTM result is handled through a separate receipt.
    subprocess.run([UTM, "exec", "Victim", "--cmd", "/usr/bin/python3", "-c", source, run_id],
                   capture_output=True, timeout=15, check=True)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            state = read_state(run_id)
            if state["stage"] == "applied":
                result["applied_state"] = state
                break
            if state["stage"] in ("apply_failed", "rolled_back", "rollback_failed"):
                raise RuntimeError("Unexpected guest stage: " + state["stage"])
        except subprocess.SubprocessError:
            pass
        time.sleep(0.5)
    else:
        raise RuntimeError("No apply receipt; do not re-dispatch. Inspect guest rollback state.")
    result["blocked_probe"] = kali_probe(secrets.token_hex(12))
    result["management_check"] = victim_read("import os,json; print(json.dumps({'connection':os.environ.get('SSH_CONNECTION'),'reachable':True}))").strip()
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        state = read_state(run_id)
        if state["stage"] == "rolled_back":
            result["rollback_state"] = state
            break
        print(json.dumps(dict(phase="waiting_for_vm_rollback", stage=state["stage"])), flush=True)
        time.sleep(5)
    else:
        raise RuntimeError("Rollback was not confirmed; operator recovery required")
    result["recovery_probe"] = kali_probe(secrets.token_hex(12))
    result["passed"] = (not result["blocked_probe"]["reachable"] and result["recovery_probe"]["reachable"]
                        and result['recovery_probe'].get('actual_source') == '192.168.64.4'
                        and json.loads(result['management_check']).get('reachable') is True)
    result["run_id"] = run_id
    with closing(connection()) as db, db:
        db.execute("UPDATE live_lab_tests SET status=?,result=? WHERE run_id=?",
                   ("complete" if result["passed"] else "verification_failed", canonical(result), run_id))
    receipt = ('verification-live-rehearsal-' + run_id + '.json') if 'assessment_snapshot' in plan else 'verification-live-lab.json'
    (HERE / receipt).write_text(json.dumps(result, indent=2)+"\n")
    return result


if __name__ == "__main__":
    from lab_config import load_profile
    if load_profile(root=HERE)['platform']!='macos-utm':
        raise SystemExit('Standalone UTM live pilot is Mac-only; use the guarded monitor with an explicitly provisioned platform adapter')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare", "check", "run"])
    parser.add_argument('--incident-id', help='Fresh current incident; uses an isolated session DB and strict live evidence checks')
    args = parser.parse_args()
    if args.incident_id:
        if not re.fullmatch(r'[0-9a-f]{64}', args.incident_id):
            parser.error('Expected full 64-character incident ID')
        DB = HERE / ('live-rehearsal-' + args.incident_id + '.sqlite3')
        source_lock = open(str(HERE / 'ssh-live.sqlite3') + '.monitor.lock', 'a')
        try:
            fcntl.flock(source_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            parser.error('Stop the monitor with Ctrl+C before using the separate live helper')
    credentials = load_credentials(json.loads((HERE / "response.local.json").read_text()))
    client = TelegramClient(credentials)
    with bot_lock(credentials.bot_key):
        if args.command == "prepare":
            result = prepare(client, credentials.identity, args.incident_id)
        elif args.command == "check":
            result = {"decisions": poll(client, credentials.identity)}
        else:
            result = execute(client, credentials.identity)
    print(json.dumps(result, indent=2), flush=True)
