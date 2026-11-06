"""Stable human labels, separate from evidence/approval identifiers."""
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
import json
import sqlite3

ZONE=ZoneInfo('America/Vancouver')


def configure_timezone(name='America/Vancouver'):
    global ZONE
    ZONE=ZoneInfo(name)


def initialize(db):
    db.execute('''CREATE TABLE IF NOT EXISTS incident_numbers(
        incident_id TEXT PRIMARY KEY,incident_number TEXT NOT NULL UNIQUE,
        local_date TEXT NOT NULL,ordinal INTEGER NOT NULL,occurred_at TEXT NOT NULL,
        time_source TEXT NOT NULL,UNIQUE(local_date,ordinal))''')


def parse(value):
    stamp=datetime.fromisoformat(value.replace('Z','+00:00'))
    if stamp.tzinfo is None:raise ValueError('Incident timestamp requires timezone')
    return stamp.astimezone(timezone.utc)


def assign(db,identifier,stamp,source='first_suricata_alert'):
    existing=db.execute('SELECT incident_number FROM incident_numbers WHERE incident_id=?',(identifier,)).fetchone()
    if existing:return existing[0]
    stamp=parse(stamp) if isinstance(stamp,str) else stamp
    if stamp.tzinfo is None:raise ValueError('Incident timestamp requires timezone')
    day=stamp.astimezone(ZONE).strftime('%Y%m%d')
    ordinal=db.execute('SELECT coalesce(max(ordinal),0)+1 FROM incident_numbers WHERE local_date=?',(day,)).fetchone()[0]
    label=f'INC-{day}-{ordinal:03d}'
    db.execute('INSERT INTO incident_numbers VALUES(?,?,?,?,?,?)',(identifier,label,day,ordinal,stamp.astimezone(timezone.utc).isoformat(),source))
    return label


def backfill(db):
    """Caller owns the write transaction. Historical labels use earliest retained alert."""
    initialize(db)
    tables={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if 'incidents' not in tables:return 0
    candidates=[]
    for identifier,encoded in db.execute('SELECT incident_id,evidence FROM incidents WHERE incident_id NOT IN (SELECT incident_id FROM incident_numbers)').fetchall():
        stamps=[]
        if {'events','grouped_events'}<=tables:
            for (payload,) in db.execute('SELECT e.payload FROM events e JOIN grouped_events g ON e.event_id=g.event_id WHERE g.incident_id=?',(identifier,)):
                try:stamps.append(parse(json.loads(payload)['timestamp']))
                except (ValueError,KeyError,TypeError):pass
        if stamps:stamp=min(stamps);source='first_suricata_alert'
        else:
            try:stamp=parse(json.loads(encoded)['window_start']);source='retained_window_start'
            except (ValueError,KeyError,TypeError):continue
        candidates.append((stamp,identifier,source))
    for stamp,identifier,source in sorted(candidates):assign(db,identifier,stamp,source)
    return len(candidates)


def attach(db,value):
    value=dict(value)
    try:row=db.execute('SELECT incident_number,occurred_at,time_source FROM incident_numbers WHERE incident_id=?',(value['incident_id'],)).fetchone()
    except sqlite3.OperationalError as exc:
        if 'no such table' not in str(exc):raise
        row=None
    if row:value.update(incident_number=row[0],incident_occurred_at=row[1],incident_time_source=row[2])
    return value


def display(value):
    return value.get('incident_number') or value['incident_id'][:16]


def time_display(value):
    stamp=value.get('incident_occurred_at')
    if not stamp:return 'Unavailable (historical record)'
    local=parse(stamp).astimezone(ZONE)
    suffix=' (retained window start)' if value.get('incident_time_source')=='retained_window_start' else ''
    return local.strftime('%Y-%m-%d %H:%M:%S %Z (UTC%z)')+' · '+ZONE.key+suffix


def header(value):
    return f"Incident: {display(value)} / revision {value['revision']}\nIncident time: {time_display(value)}\n"
