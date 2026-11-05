"""Durable SSH correlation scopes; no verdicts or response execution."""
from datetime import timedelta
import hashlib
import json

from approved_plans import select_plan, validate_plan
from ssh_scenarios import timestamp

VERSION = 'ssh_correlation_v1'
WINDOW_SECONDS = 120
ARRIVAL_SECONDS = 30
PRE_ALERT_SECONDS = 60


class CorrelationError(RuntimeError):
    """Stop grouping on ambiguous authorization instead of discarding alerts."""


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def scope(evidence):
    result = evidence.get('correlation')
    if result is None:
        return None  # Historical minute incidents retain their original behavior.
    if result.get('version') != VERSION or result.get('kind') not in ('approved_plan', 'fixed_window'):
        raise ValueError('Unknown SSH correlation scope')
    start, end = timestamp(evidence['window_start']), timestamp(result['end'])
    evidence_start = timestamp(result['evidence_start'])
    if not evidence_start <= start < end:
        raise ValueError('Invalid SSH correlation interval')
    if result['kind'] == 'fixed_window':
        if end-start > timedelta(seconds=WINDOW_SECONDS) or start-evidence_start > timedelta(seconds=PRE_ALERT_SECONDS):
            raise ValueError('SSH correlation exceeds fixed bounds')
        if result.get('plan_snapshot') is not None:
            raise ValueError('Unapproved correlation cannot contain a plan')
    else:
        plan = validate_plan(result['plan_snapshot'])
        if (plan['approval_status'] != 'approved' or start != timestamp(plan['start'])
                or end != timestamp(plan['end']) or evidence_start != start
                or result.get('plan_hash') != digest(plan)):
            raise ValueError('SSH correlation plan snapshot does not match its interval')
    return result


def recorded_plan(evidence, plans):
    """Use the original plan scope; changing/revoking it requires manual review."""
    saved = scope(evidence)
    if saved is None:
        raise ValueError('Expected a correlated SSH incident')
    plan = saved.get('plan_snapshot')
    if plan is not None:
        current = next((p for p in plans if p['id'] == plan['id']), None)
        if current is None or digest(current) != saved['plan_hash']:
            raise ValueError('Approved correlation plan changed or was revoked; manual review required')
    else:
        start, end = timestamp(evidence['window_start']), timestamp(saved['end'])
        if any(p['approval_status']=='approved' and evidence['source_ip'] in p['source_ips']
               and evidence['destination_ip']==p['target_ip'] and evidence['destination_port']==p['target_port']
               and timestamp(p['start'])<end and timestamp(p['end'])>start for p in plans):
            raise ValueError('Authorization changed during fixed correlation; manual review required')
    return plan


def ready_at(evidence):
    saved = scope(evidence)
    if saved is None:
        raise ValueError('Expected a correlated SSH incident')
    return timestamp(saved['end']) + timedelta(seconds=ARRIVAL_SECONDS)


def initialize(db):
    db.executescript('''CREATE TABLE IF NOT EXISTS ssh_correlations (
        incident_id TEXT PRIMARY KEY, source TEXT NOT NULL, destination TEXT NOT NULL,
        port INTEGER NOT NULL, signature_id INTEGER NOT NULL,
        evidence_start REAL NOT NULL, start REAL NOT NULL, end REAL NOT NULL);
        CREATE INDEX IF NOT EXISTS ssh_correlation_scope
        ON ssh_correlations(source,destination,port,signature_id,evidence_start,end);''')


def assign(db, source, destination, port, sid, stamp, plans):
    """Half-open fixed windows survive restarts; newer alerts never extend them."""
    identity = (source, destination, port, sid)
    matches = db.execute('''SELECT c.incident_id,i.evidence FROM ssh_correlations c JOIN incidents i
        ON i.incident_id=c.incident_id WHERE c.source=? AND c.destination=? AND c.port=?
        AND c.signature_id=? AND c.evidence_start<=? AND c.end>?''',
        (*identity, stamp.timestamp(), stamp.timestamp())).fetchall()
    if len(matches) > 1:
        raise CorrelationError('Overlapping saved SSH correlations require operator review')
    if matches:
        incident_id, encoded = matches[0]
        existing = json.loads(encoded)
        scope(existing)
        return incident_id, existing
    context = dict(source_ip=source, target_ip=destination, target_port=port,
                   start=stamp.isoformat(), end=stamp.isoformat())
    try:
        plan = select_plan(context, plans)
    except ValueError as exc:
        raise CorrelationError(str(exc)) from exc
    if plan:
        start, end = timestamp(plan['start']), timestamp(plan['end'])
        evidence_start = start
        saved = dict(version=VERSION, kind='approved_plan', end=end.isoformat(),
                     evidence_start=start.isoformat(), plan_snapshot=plan, plan_hash=digest(plan))
        key = [VERSION, *identity, plan['id'], digest(plan)]
    else:
        start, end = stamp, stamp + timedelta(seconds=WINDOW_SECONDS)
        evidence_start = start-timedelta(seconds=PRE_ALERT_SECONDS)
        # Keep context for the logins that caused the first Suricata alert, without
        # counting the same retained records again in the next investigation.
        previous = db.execute('''SELECT max(end) FROM ssh_correlations WHERE source=?
            AND destination=? AND port=? AND signature_id=? AND end<=?''',
            (*identity, stamp.timestamp())).fetchone()[0]
        following = db.execute('''SELECT min(evidence_start) FROM ssh_correlations WHERE source=?
            AND destination=? AND port=? AND signature_id=? AND evidence_start>?''',
            (*identity, stamp.timestamp())).fetchone()[0]
        if previous is not None:
            evidence_start = max(evidence_start, timestamp_from_epoch(previous))
        if following is not None:
            end = min(end, timestamp_from_epoch(following))
        # An authorization boundary must not absorb planned and unplanned traffic.
        for p in plans:
            if p['approval_status'] != 'approved' or source not in p['source_ips'] or destination != p['target_ip'] or port != p['target_port']:
                continue
            pstart, pend = timestamp(p['start']), timestamp(p['end'])
            if pstart > start:
                end = min(end, pstart)
            if pend <= start:
                evidence_start = max(evidence_start, pend)
        saved = dict(version=VERSION, kind='fixed_window', end=end.isoformat(),
                     evidence_start=evidence_start.isoformat(), plan_snapshot=None)
        key = [VERSION, *identity, start.isoformat()]
    incident_id = digest(key)
    evidence = dict(source_ip=source, destination_ip=destination, destination_port=port,
                    signature_id=sid, window_start=start.isoformat(), sample_event_ids=[], correlation=saved)
    scope(evidence)
    db.execute('INSERT INTO ssh_correlations VALUES(?,?,?,?,?,?,?,?)',
               (incident_id, *identity, evidence_start.timestamp(), start.timestamp(), end.timestamp()))
    return incident_id, evidence


def timestamp_from_epoch(value):
    from datetime import datetime, timezone
    return datetime.fromtimestamp(value, timezone.utc)
