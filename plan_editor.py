"""Dashboard-native immutable drafts and explicit operator test-plan approval."""
from contextlib import closing, contextmanager
from datetime import datetime, timezone
import fcntl
import ipaddress
import json
from pathlib import Path
import re
import secrets
import sqlite3
from approved_plans import load_plans, validate_plan
from ssh_scenarios import timestamp

def normalize(values, config, now=None, plan_id=None):
    now = now or datetime.now(timezone.utc)
    expected = {'source_ip', 'target_ip', 'allowed_accounts', 'maximum_failed_attempts',
                'start', 'end', 'owner'}
    if not isinstance(values, dict) or set(values) != expected:
        raise ValueError('Complete all plan fields; unexpected fields are not accepted.')
    if any(not isinstance(values[k], str) for k in expected - {'maximum_failed_attempts'}):
        raise ValueError('Plan fields must be text.')
    source = str(ipaddress.ip_address(values['source_ip'].strip()))
    target = str(ipaddress.ip_address(values['target_ip'].strip()))
    if source not in config['source_ips'] or target != config['destination_ip'] or source == target:
        raise ValueError('Choose a monitored lab source and the configured victim target.')
    accounts = [a.strip() for a in values['allowed_accounts'].split(',')]
    if not 1 <= len(accounts) <= 8 or any(not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', a) for a in accounts):
        raise ValueError('Enter 1–8 account names separated by commas (letters, digits, _, . or -).')
    accounts = sorted(set(accounts))
    limit = values['maximum_failed_attempts']
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError('Attempt limit must be a whole number from 1 to 100.')
    owner = values['owner'].strip()
    if not 1 <= len(owner) <= 80 or any(ord(c) < 32 for c in owner):
        raise ValueError('Enter an operator name of 1–80 characters.')
    start, end = timestamp(values['start']), timestamp(values['end'])
    if start <= now:
        raise ValueError('Start time must be in the future. Use fresh times and validate again.')
    if any(t.second or t.microsecond for t in (start, end)):
        raise ValueError('Use whole-minute start and end times for incident correlation.')
    if not 60 <= (end-start).total_seconds() <= 600:
        raise ValueError('Choose a test window lasting 1–10 minutes.')
    plan = {'id': plan_id or 'SSH-'+secrets.token_hex(8), 'approval_status': 'draft',
            'owner': owner, 'source_ips': [source], 'target_ip': target, 'target_port': 22,
            'start': start.astimezone(timezone.utc).isoformat(),
            'end': end.astimezone(timezone.utc).isoformat(), 'allowed_accounts': accounts,
            'maximum_failed_attempts': limit,
            'source_format': 'dashboard_native', 'version': 1,
            'scope': 'Authorized failed-password detection test using only the permitted accounts. No successful login is authorized.',
            'stop_conditions': ['Stop at the failed-attempt limit', 'Stop on unexpected account or successful login']}
    return validate_plan(plan)



@contextmanager
def registry_lock(path):
    with Path(str(path)+'.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def check_conflicts(plan, existing):
    for other in existing:
        if other['id'] == plan['id']:
            raise ValueError('Use a new plan ID for each version/window')
        if (other['approval_status']=='approved' and plan['target_ip']==other['target_ip']
                and set(plan['source_ips']) & set(other['source_ips'])
                and max(timestamp(plan['start']),timestamp(other['start'])) < min(timestamp(plan['end']),timestamp(other['end']))):
            raise ValueError('Overlapping approved windows for the same source and target')


def write_registry(path, plans):
    encoded = json.dumps(plans, indent=2)+'\n'
    if len(plans)>32 or len(encoded.encode())>65536:
        raise ValueError('Registry exceeds 32 plans or 64KB; archive expired plans before adding more')
    temp=path.with_name(path.name+'.tmp')
    temp.write_text(encoded)
    temp.replace(path)


class PlanEditor:
    def __init__(self, root):
        self.root=Path(root).resolve()
        self.db=self.root/'plan-editor.sqlite3'
        with closing(sqlite3.connect(self.db)) as db, db:
            # Old Word drafts remain intact in their original table for audit.
            db.execute('CREATE TABLE IF NOT EXISTS native_drafts (id TEXT PRIMARY KEY, token TEXT NOT NULL, plan TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, approved_plan TEXT)')

    def registry(self):
        config=json.loads((self.root/'runtime.ssh.live.local.json').read_text())
        path=Path(config['approved_plans'])
        return path if path.is_absolute() else self.root/path

    def config(self):
        return json.loads((self.root/'live.ssh.local.json').read_text())

    def validate(self, values, now=None):
        now=now or datetime.now(timezone.utc)
        plan=normalize(values,self.config(),now)
        existing=load_plans(self.registry()) if self.registry().exists() else []
        check_conflicts(plan,existing)
        identifier,token=secrets.token_hex(16),secrets.token_hex(32)
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('INSERT INTO native_drafts VALUES (?,?,?,?,?,NULL)',
                       (identifier,token,json.dumps(plan),'validated',now.isoformat()))
        return {'draft_id':identifier,'validation_token':token,'plan':plan}

    def get(self, identifier):
        if not isinstance(identifier,str) or not re.fullmatch('[a-f0-9]{32}',identifier):
            raise ValueError('Unknown plan draft')
        with closing(sqlite3.connect(self.db)) as db:
            db.row_factory=sqlite3.Row
            row=db.execute('SELECT * FROM native_drafts WHERE id=?',(identifier,)).fetchone()
        if row is None: raise ValueError('Unknown plan draft')
        return dict(row)

    def approve(self, identifier, token, now=None):
        now=now or datetime.now(timezone.utc)
        with closing(sqlite3.connect(self.db,timeout=10)) as db, db:
            db.execute('BEGIN IMMEDIATE')
            row=self.get(identifier)
            if not isinstance(token,str) or not secrets.compare_digest(row['token'],token):
                raise ValueError('Validate the current plan before approving it')
            if row['status']=='approved': return json.loads(row['approved_plan'])
            plan=json.loads(row['plan'])
            if timestamp(plan['start'])<=now:
                raise ValueError('This preview expired. Use fresh times and validate again.')
            # Revalidate scope against current configured lab limits.
            fields={'source_ip':plan['source_ips'][0],'target_ip':plan['target_ip'],
                    'allowed_accounts':', '.join(plan['allowed_accounts']),
                    'maximum_failed_attempts':plan['maximum_failed_attempts'],
                    'start':plan['start'],'end':plan['end'],'owner':plan['owner']}
            if normalize(fields,self.config(),now,plan_id=plan['id'])!=plan:
                raise ValueError('Validated scope changed; validate again')
            plan.update(approval_status='approved',approved_by=plan['owner'],approved_at=now.isoformat())
            validate_plan(plan)
            with registry_lock(self.registry()):
                existing=load_plans(self.registry()) if self.registry().exists() else []
                saved=next((p for p in existing if p['id']==plan['id']),None)
                if saved:
                    # Recover only the exact version after an interrupted DB commit.
                    comparable={k:v for k,v in saved.items() if k!='approved_at'}
                    if comparable!={k:v for k,v in plan.items() if k!='approved_at'}:
                        raise ValueError('Plan ID already has a different immutable version')
                    plan=saved
                else:
                    check_conflicts(plan,existing)
                    write_registry(self.registry(),existing+[plan])
            db.execute('UPDATE native_drafts SET status=?,approved_plan=? WHERE id=?',
                       ('approved',json.dumps(plan),identifier))
            return plan
