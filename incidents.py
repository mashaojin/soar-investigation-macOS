from contextlib import closing
"""Create durable SSH correlations and preserve historical incident records."""
import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import sqlite3
from dvwa import SID, ASSET


def group_events(db_path, *, ssh_plans_path=None):
    from approved_plans import load_plans
    import ssh_correlation
    plans = load_plans(ssh_plans_path) if ssh_plans_path else []
    counts = dict(grouped=0, rejected=0)
    with closing(sqlite3.connect(db_path)) as db, db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY, evidence TEXT NOT NULL,
                alert_count INTEGER NOT NULL, revision INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending'
            );
            CREATE TABLE IF NOT EXISTS grouped_events (
                event_id TEXT PRIMARY KEY, incident_id TEXT, error TEXT
            );
        """)
        ssh_correlation.initialize(db)
        from incident_labels import initialize as initialize_labels,assign as assign_label,backfill as backfill_labels
        initialize_labels(db)
        db.execute("BEGIN IMMEDIATE")
        backfill_labels(db)
        rows = db.execute("""
            SELECT event_id, payload FROM events
            WHERE event_id NOT IN (SELECT event_id FROM grouped_events)
        """)
        def event_order(row):
            try:
                return datetime.fromisoformat(json.loads(row[1])['timestamp'].replace('Z','+00:00')).timestamp(), row[0]
            except (ValueError,KeyError,TypeError,AttributeError,OverflowError):
                return float('inf'), row[0]
        for event_id, payload in sorted(rows.fetchall(), key=event_order):
            try:
                event = json.loads(payload)
                stamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
                if stamp.tzinfo is None:
                    raise ValueError("timezone required")
                minute = int(stamp.timestamp()) // 60 * 60
                source = str(ipaddress.ip_address(event["src_ip"]))
                destination = str(ipaddress.ip_address(event["dest_ip"]))
                port = event["dest_port"]
                sid = event["alert"]["signature_id"]
                if type(port) is not int or not 0 < port < 65536 or type(sid) is not int:
                    raise ValueError("invalid port/signature ID")
                key = [source, destination, port, sid, minute]
                if sid == SID:
                    # One request per incident when Suricata transaction IDs exist.
                    # Missing IDs use the unique event, never merge unrelated requests.
                    flow, tx = event.get("flow_id"), event.get("tx_id")
                    key = [source, destination, port, sid, flow, tx] if type(flow) is int and type(tx) is int else [event_id, sid]
                incident_id = hashlib.sha256(json.dumps(key).encode()).hexdigest()
                existing = db.execute(
                    "SELECT evidence, alert_count FROM incidents WHERE incident_id=?",
                    (incident_id,),
                ).fetchone()
                evidence = json.loads(existing[0]) if existing else {
                    "source_ip": source, "destination_ip": destination,
                    "destination_port": port, "signature_id": sid,
                    "window_start": datetime.fromtimestamp(minute, timezone.utc).isoformat(),
                    "sample_event_ids": [],
                }
                if sid == 9001001 and port == 22:
                    incident_id, evidence = ssh_correlation.assign(db, source, destination, port, sid, stamp, plans)
                    existing = db.execute('SELECT evidence,alert_count FROM incidents WHERE incident_id=?', (incident_id,)).fetchone()
                if sid == 9001001:
                    provenance=evidence.setdefault('rule_provenance',{'signature_id':sid,'observed_revisions':[],
                        'status':'EVE signature revisions; exact rule text/hash requires a captured editor version.'})
                    rev=event.get('alert',{}).get('rev')
                    if type(rev) is int and rev not in provenance['observed_revisions']:
                        provenance['observed_revisions'].append(rev)
                if sid == SID:
                    evidence.update(scenario="dvwa_sqli", asset_id=ASSET,
                                    flow_id=event.get("flow_id"), tx_id=event.get("tx_id"),
                                    http=event.get("http", {"evidence_available": False}))
                if len(evidence["sample_event_ids"]) < 3:
                    evidence["sample_event_ids"].append(event_id)
                count = existing[1] + 1 if existing else 1
                # Late evidence increments revision; future analysis must bind to
                # a revision and not silently reuse an obsolete report/approval.
                db.execute("""
                    INSERT INTO incidents VALUES (?, ?, ?, 1, 'pending')
                    ON CONFLICT(incident_id) DO UPDATE SET
                    evidence=excluded.evidence, alert_count=excluded.alert_count,
                    revision=incidents.revision+1, status='pending'
                """, (incident_id, json.dumps(evidence, sort_keys=True), count))
                assign_label(db,incident_id,stamp)
                db.execute("INSERT INTO grouped_events VALUES (?, ?, NULL)",
                           (event_id, incident_id))
                counts["grouped"] += 1
            except (ValueError, KeyError, TypeError, AttributeError, OverflowError):
                db.execute("INSERT INTO grouped_events VALUES (?, NULL, ?)",
                           (event_id, "Missing or invalid incident fields"))
                counts["rejected"] += 1
    return counts


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True)
    args = parser.parse_args()
    print(json.dumps(group_events(args.db), sort_keys=True))
