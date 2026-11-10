"""Foreground observation service: independent collection and analysis loops."""
import argparse
from datetime import datetime, timezone
import fcntl
import json
from pathlib import Path
import sqlite3
import subprocess
import threading
import time
import secrets

from analyst import analyze_next, recover_interrupted_analyses
from topology import collector_config, response_config
from live import collect_once, RemoteGap
from response import tick
from telegram_client import TelegramClient, TelegramError, bot_lock, load_credentials
from service_state import record
from assessment_facts import VERSION
from ssh_correlation import VERSION as CORRELATION_VERSION


def run(config, db_path, runtime, *, duration=None, response_policy=None):
    config = dict(config)
    if runtime.get('ssh_enrichment'):
        config['approved_plans'] = runtime['approved_plans']
    stop = threading.Event()
    caught_up = threading.Event()
    telegram_owned=threading.Event()
    errors = []
    instance=secrets.token_hex(12)
    def health(component,status,**detail):
        record(db_path,instance,component,status,**detail)
    def heartbeat_loop():
        while not stop.is_set():
            try: health('monitor','running',assessment_version=VERSION,correlation_version=CORRELATION_VERSION,response_mode=response_policy['mode'] if response_policy else 'disabled')
            except sqlite3.Error: pass
            stop.wait(5)
    def emit(kind, **fields):
        print(json.dumps({"time": datetime.now(timezone.utc).isoformat(), "kind": kind, **fields}), flush=True)

    def collector_loop():
        backoff = 5
        while not stop.is_set():
            try:
                batch = collect_once(config, db_path)
                caught_up.clear() if batch["has_more"] else caught_up.set()
                emit("collection", **batch)
                health('collector','catching_up' if batch['has_more'] else 'watching',**batch)
                backoff = 5
                stop.wait(0.1 if batch["has_more"] else config.get("poll_seconds", 5))
            except RemoteGap as exc:
                caught_up.clear()
                errors.append(str(exc))
                emit("collection_gap", error=str(exc), action="Operator recovery required; service stopped")
                health('collector','gap',error=str(exc))
                stop.set()
            except (OSError, ValueError, RuntimeError, sqlite3.Error, subprocess.SubprocessError) as exc:
                caught_up.clear()
                emit("collection_error", error=str(exc)[:1000], retry_seconds=backoff)
                health('collector','error',error=str(exc)[:1000])
                stop.wait(backoff)
                backoff = min(backoff * 2, 60)

    def response_loop():
        try:
            credentials = load_credentials(response_policy)
            client = TelegramClient(credentials)
            with bot_lock(credentials.bot_key):
                telegram_owned.set()
                checked = False
                backoff = 5
                while not stop.is_set():
                    try:
                        if not checked:
                            client.check()
                            checked = True
                        result = tick(db_path, response_policy, client, credentials.identity)
                        health('telegram','polling')
                        if result["queued"] or result["delivery"] != "idle" or result["decisions"] or result["dry_run_actions"] or result.get('telegram_status_updates') or result.get('review_notification','idle')!='idle':
                            emit("telegram_response", **result)
                        backoff = 5
                        stop.wait(3)
                    except (TelegramError, sqlite3.Error) as exc:
                        emit("telegram_error", error=str(exc)[:1000], retry_seconds=backoff)
                        health('telegram','error',error=str(exc)[:1000])
                        stop.wait(backoff)
                        backoff = min(backoff * 2, 60)
        except (OSError, ValueError, TelegramError) as exc:
            emit("telegram_stopped", error=str(exc)[:1000])
            health('telegram','stopped',error=str(exc)[:1000])
        finally:
            telegram_owned.clear()

    def live_loop():
        from live_response import run_one, reconcile
        identity=load_credentials(response_policy).identity
        while not stop.is_set():
            try:
                health('live_worker','ready')
                reconcile(db_path)
                if telegram_owned.is_set() and run_one(db_path,response_policy,identity):
                    emit('live_response',action='Worker finished; outcome recorded in dashboard')
            except (OSError,ValueError,RuntimeError,sqlite3.Error,subprocess.SubprocessError) as exc:
                emit('live_response_error',error=str(exc)[:1000])
                health('live_worker','error',error=str(exc)[:1000])
            stop.wait(3)

    # Prevent two monitor processes from sharing this database's collector/worker.
    with open(str(db_path) + ".monitor.lock", "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("A monitor already holds this database lock") from None
        recovered = recover_interrupted_analyses(db_path)
        health('monitor','running',assessment_version=VERSION,correlation_version=CORRELATION_VERSION,response_mode=response_policy['mode'] if response_policy else 'disabled')
        health('telegram','starting' if response_policy else 'disabled')
        heartbeat=threading.Thread(target=heartbeat_loop,name='soc-heartbeat',daemon=True)
        heartbeat.start()
        if recovered: emit("interrupted_assessments", count=recovered, action="Manual review; no automatic retry")
        thread = threading.Thread(target=collector_loop, name="soc-collector", daemon=True)
        thread.start()
        response_thread = None
        if response_policy is not None:
            response_thread = threading.Thread(target=response_loop, name="soc-response", daemon=True)
            response_thread.start()
        live_thread=None
        if response_policy is not None and response_policy['mode']=='live':
            live_thread=threading.Thread(target=live_loop,name='soc-live-worker',daemon=True)
            live_thread.start()
        deadline = time.monotonic() + duration if duration is not None else None
        try:
            while not stop.is_set() and (deadline is None or time.monotonic() < deadline):
                if caught_up.is_set():
                    try:
                        result = analyze_next(db_path, runtime)
                    except sqlite3.Error as exc:
                        emit("analysis_database_error", error=str(exc)[:1000])
                        stop.wait(5)
                        continue
                    # Idle checks are local database reads, not inference requests.
                    if result["status"] != "idle":
                        emit("analysis", **result)
                    health('analyst',result['status'])
                    stop.wait(1 if result["status"] != "idle" else 5)
                else:
                    stop.wait(0.2)
        except KeyboardInterrupt:
            emit("stopping")
        finally:
            stop.set()
            thread.join(timeout=25)
            if response_thread is not None:
                response_thread.join(timeout=15)
            if live_thread is not None:
                live_thread.join(timeout=3)
            heartbeat.join(timeout=6)
            health('monitor','stopped')
        return 1 if errors else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="live.ssh.local.json")
    parser.add_argument("--db", default="ssh-live.sqlite3")
    parser.add_argument("--runtime", default="runtime.ssh.live.local.json")
    parser.add_argument("--duration", type=float, help="Optional bounded verification duration, seconds")
    parser.add_argument("--telegram", action="store_true", help="Enable the single Telegram handler and configured response worker")
    parser.add_argument("--response-config", default="response.local.json")
    args = parser.parse_args()
    config = collector_config(json.loads(Path(args.config).read_text()))
    if not 1 <= config.get("poll_seconds", 5) <= 60:
        parser.error("poll_seconds must be between 1 and 60")
    response_policy = response_config(json.loads(Path(args.response_config).read_text())) if args.telegram else None
    if response_policy is not None and (response_policy.get("mode") not in ('dry_run','live')
                                       or response_policy.get("exclusive_polling_confirmed") is not True):
        parser.error("Telegram requires a supported response mode and confirmed exclusive polling")
    if response_policy is not None and response_policy['mode']=='live':
        if response_policy.get('duration_seconds')!=60 or not response_policy.get('live_enabled_after'):
            parser.error('Live lab mode requires 60-second rollback and an explicit activation time')
    raise SystemExit(run(config, str(Path(args.db).resolve()),
                         json.loads(Path(args.runtime).read_text()), duration=args.duration,
                         response_policy=response_policy))
