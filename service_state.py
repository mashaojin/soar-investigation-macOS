"""Explicit monitor heartbeat and component health; never inferred from HTTP."""
from contextlib import closing
import json
import sqlite3
import time


def record(path,instance,component,status,**detail):
    with closing(sqlite3.connect(path,timeout=10)) as db,db:
        db.execute('''CREATE TABLE IF NOT EXISTS service_state (
            component TEXT PRIMARY KEY, instance TEXT NOT NULL, status TEXT NOT NULL,
            updated_at REAL NOT NULL, detail TEXT NOT NULL)''')
        db.execute('''INSERT INTO service_state VALUES(?,?,?,?,?) ON CONFLICT(component)
            DO UPDATE SET instance=excluded.instance,status=excluded.status,updated_at=excluded.updated_at,detail=excluded.detail''',
            (component,instance,status,time.time(),json.dumps(detail)))


def view(db,now=None):
    now=time.time() if now is None else now
    rows={r['component']:dict(r) for r in db.execute('SELECT * FROM service_state')}
    main=rows.get('monitor')
    if not main: return {'running':False,'state':'unknown','label':'Monitor status unavailable','components':{}}
    age=max(0,now-main['updated_at'])
    running=main['status']=='running' and age<=20
    state='running' if running else 'stopped' if main['status']=='stopped' else 'stale'
    components={k:{'status':r['status'],'updated_at':r['updated_at'],'detail':json.loads(r['detail'])}
                for k,r in rows.items() if k!='monitor' and r['instance']==main['instance']}
    return {'running':running,'state':state,'label':'Monitor running' if running else 'Monitor stopped' if state=='stopped' else 'Monitor heartbeat overdue',
            'assessment_version':json.loads(main['detail']).get('assessment_version'),
            'correlation_version':json.loads(main['detail']).get('correlation_version'),
            'heartbeat_age_seconds':round(age,1),'last_heartbeat':main['updated_at'],'components':components}
