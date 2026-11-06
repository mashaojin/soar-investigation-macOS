from dvwa import sanitize_event
"""Collect one bounded remote batch over SSH and atomically commit its cursor."""
import argparse
import base64
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import sqlite3
import subprocess
import tempfile

from incidents import group_events


class RemoteGap(RuntimeError):
    pass


def source_key(config):
    return f"ssh://{config['ssh_target']}{config['log_path']}"


def initialize(db):
    db.executescript("""
        CREATE TABLE IF NOT EXISTS remote_checkpoints (
            source TEXT PRIMARY KEY, cursor TEXT NOT NULL,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY, payload TEXT NOT NULL,
            collected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS remote_audit (
            source TEXT NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL,
            recorded_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    """)


def socket_path(config):
    identity=config['ssh_target']
    if config.get('lab_profile'):
        identity=json.dumps({'target':identity,'profile':config['lab_profile']},sort_keys=True)
    key = hashlib.sha256(identity.encode()).hexdigest()[:16]
    folder = Path(tempfile.gettempdir()) / f"soc-ssh-{os.getuid()}"
    folder.mkdir(mode=0o700, exist_ok=True)
    stat = folder.lstat()
    if folder.is_symlink() or stat.st_uid != os.getuid() or stat.st_mode & 0o077:
        raise ValueError("SSH socket directory must be private and owned by this user")
    return str(folder / key)


def ssh_command(config, remote_code):
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*@[A-Za-z0-9][A-Za-z0-9.-]*", config["ssh_target"]):
        raise ValueError("Expected SSH target user@host")
    if config.get('lab_profile'):
        from lab_config import load_profile
        from ssh_transport import command
        lab=load_profile(config)
        if config['ssh_target']!=lab['victim']['user']+'@'+lab['victim']['ip']:
            raise ValueError('Collector SSH target differs from trusted lab profile')
        argv=command(lab,'victim','python3 -c '+shlex.quote(remote_code))
        return argv[:-2]+['-o','ControlMaster=auto','-o','ControlPersist=60',
                         '-o','ControlPath='+socket_path(dict(config,lab_profile=lab))]+argv[-2:]
    return ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "ConnectTimeout=5", "-o", "ServerAliveInterval=5",
            "-o", "ServerAliveCountMax=2", "-o", "ControlMaster=auto",
            "-o", "ControlPersist=60", "-o", "ControlPath=" + socket_path(config),
            config["ssh_target"], "python3 -c " + shlex.quote(remote_code)]


def fetch(config, cursor):
    code = Path(__file__).with_name("remote_reader.py").read_text()
    request = {"path": config["log_path"], "cursor": cursor,
               "start_at": config.get("start_at", "end")}
    if request["start_at"] not in ("end", "beginning"):
        raise ValueError("start_at must be end or beginning")
    # Temp files keep unexpected SSH output from growing the parent's memory.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        result = subprocess.run(ssh_command(config, code), input=json.dumps(request).encode(),
                                stdout=output, stderr=errors, timeout=20, check=False)
        if result.returncode:
            errors.seek(0)
            raise ConnectionError(errors.read(2048).decode(errors="replace").strip())
        output.seek(0)
        raw = output.read(2 * 1048576 + 1)
        if len(raw) > 2 * 1048576:
            raise ValueError("Remote response exceeds size budget")
    response = json.loads(raw)
    if not response.get("ok"):
        if response.get("kind") == "gap":
            raise RemoteGap(response.get("error", "Remote collection gap"))
        raise OSError(response.get("error", "Remote read failed"))
    return response


def collect_once(config, db_path, *, reader=fetch):
    source = source_key(config)
    with closing(sqlite3.connect(db_path, timeout=10)) as db, db:
        initialize(db)
        row = db.execute("SELECT cursor FROM remote_checkpoints WHERE source=?", (source,)).fetchone()
    previous = row[0] if row else None
    try:
        batch = reader(config, json.loads(previous) if previous else None)
    except (OSError, ValueError, RemoteGap, subprocess.SubprocessError) as exc:
        with closing(sqlite3.connect(db_path, timeout=10)) as db, db:
            db.execute("INSERT INTO remote_audit(source,kind,detail) VALUES(?,?,?)",
                       (source, "gap" if isinstance(exc, RemoteGap) else "read_error", str(exc)[:2000]))
        raise
    counts = dict(inserted=0, duplicates=0, ignored=0, malformed=0, filtered=0)
    with closing(sqlite3.connect(db_path, timeout=10)) as db, db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT cursor FROM remote_checkpoints WHERE source=?", (source,)).fetchone()
        if (row[0] if row else None) != previous:
            raise RuntimeError("Another collector advanced the cursor; this batch was not committed")
        for encoded in batch["lines"]:
            try:
                line = base64.b64decode(encoded, validate=True)
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError("Expected JSON object")
            except (ValueError, UnicodeDecodeError):
                counts["malformed"] += 1
                continue
            if event.get("event_type") != "alert":
                counts["ignored"] += 1
                continue
            allowed = config.get("signature_ids", [9001001])
            alert = event.get("alert")
            if not isinstance(alert, dict) or alert.get("signature_id") not in allowed:
                counts["filtered"] += 1
                continue
            if config.get("source_ips") is not None and event.get("src_ip") not in config["source_ips"]:
                counts["filtered"] += 1
                continue
            if config.get("destination_ip") is not None and event.get("dest_ip") != config["destination_ip"]:
                counts["filtered"] += 1
                continue
            event = sanitize_event(event)
            payload = json.dumps(event, sort_keys=True, separators=(",", ":"))
            event_id = hashlib.sha256(payload.encode()).hexdigest()
            result = db.execute("INSERT OR IGNORE INTO events(event_id,payload) VALUES(?,?)",
                                (event_id, payload))
            counts["inserted" if result.rowcount else "duplicates"] += 1
        encoded_cursor = json.dumps(batch["cursor"], sort_keys=True)
        db.execute("""INSERT INTO remote_checkpoints(source,cursor) VALUES(?,?)
                      ON CONFLICT(source) DO UPDATE SET cursor=excluded.cursor,
                      updated_at=CURRENT_TIMESTAMP""", (source, encoded_cursor))
        if not previous or batch.get("rotation_advanced") or counts["malformed"]:
            db.execute("INSERT INTO remote_audit(source,kind,detail) VALUES(?,?,?)",
                       (source, "baseline" if not previous else "batch_notice",
                        json.dumps({"skipped_bytes": batch.get("baseline_skipped_bytes", 0), **counts})))
    grouped = group_events(db_path, ssh_plans_path=config.get("approved_plans"))
    return {**counts, **grouped, "has_more": batch["has_more"],
            "baseline_skipped_bytes": batch.get("baseline_skipped_bytes", 0)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="live.ssh.local.json")
    parser.add_argument("--db", default="ssh-live.sqlite3")
    args = parser.parse_args()
    print(json.dumps(collect_once(json.loads(Path(args.config).read_text()), args.db), sort_keys=True))
