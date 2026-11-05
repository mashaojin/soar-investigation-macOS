"""Host-side fixed-rule editing. All privileged mutations happen in the VM helper."""
from contextlib import closing
import difflib
import json
from pathlib import Path
import secrets
import sqlite3
import subprocess
import time

from experiment_store import encode,now
from soc_rule_helper import parse_rule,sha


class RuleEditor:
    def __init__(self,root,transport=None):
        self.root=Path(root);self.path=self.root/'lab-experiments.sqlite3';self.transport=transport or self.remote

    def remote(self,request):
        if not (self.root/'rule-editor-enabled.json').exists():
            raise ValueError('Victim rule helper is not provisioned for this dashboard root.')
        result=subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=5','victim@192.168.64.6',
            'sudo -n /usr/bin/python3 /usr/local/libexec/soc-rule-editor.py'],
            input=encode(request),capture_output=True,text=True,timeout=150)
        if result.returncode: raise RuntimeError('Victim helper unavailable: '+result.stderr[-1000:])
        if len(result.stdout.encode())>65536: raise ValueError('Oversized helper response')
        envelope=json.loads(result.stdout)
        if envelope.get('ok') is not True: raise ValueError(envelope.get('error','Victim rejected request'))
        return envelope['result']

    def cache(self,value):
        with closing(sqlite3.connect(self.path)) as db,db:
            if value.get('activation_verified'):
                db.execute('INSERT OR IGNORE INTO rule_versions VALUES(?,?,?,?)',(value['hash'],value['fields']['revision'],value['text'],value['last_activation']['activated_at']))
            db.execute('INSERT INTO rule_cache VALUES(1,?) ON CONFLICT(singleton) DO UPDATE SET value=excluded.value',(encode(value),))

    def read(self,values):
        if values!={}: raise ValueError('Read does not accept fields')
        status=self.transport({'action':'read'});self.cache(status)
        return status

    def validate(self,values):
        if not isinstance(values,dict) or set(values)!={'text','expected_hash'}: raise ValueError('Supply rule draft and base hash.')
        parse_rule(values['text'])
        status=self.transport({'action':'read'})
        if status['hash']!=values['expected_hash']: raise ValueError('Rule changed. Read from Victim again.')
        result=self.transport(dict(action='validate',text=values['text'],expected_hash=status['hash']))
        identifier=secrets.token_hex(12);token=secrets.token_hex(24)
        diff=''.join(difflib.unified_diff(status['text'].splitlines(True),values['text'].splitlines(True),fromfile='Victim current rule',tofile='Validated draft'))
        result.update(diff=diff,validation_token=token,expires_at=time.time()+600)
        with closing(sqlite3.connect(self.path)) as db,db:
            db.execute('INSERT INTO rule_drafts VALUES(?,?,?,?,?,?,?)',
                (identifier,now(),values['text'],status['hash'],token,'validated',encode(result)))
        self.cache(status)
        return dict(id=identifier,**result)

    def apply(self,values):
        if not isinstance(values,dict) or set(values)!={'id','validation_token'}: raise ValueError('Apply the exact validated rule draft.')
        with closing(sqlite3.connect(self.path)) as db,db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT text,base_hash,token,status,result FROM rule_drafts WHERE id=?',(values['id'],)).fetchone()
            if not row or row[3]!='validated' or not secrets.compare_digest(row[2],values['validation_token']):
                raise ValueError('Validated draft missing, used or changed. Validate again.')
            validated=json.loads(row[4])
            if time.time()>=validated['expires_at']: raise ValueError('Rule validation expired. Validate again.')
            db.execute("UPDATE rule_drafts SET status='applying',token=NULL WHERE id=?",(values['id'],))
        try:
            result=self.transport(dict(action='apply',text=row[0],expected_hash=row[1],configuration_hash=validated['configuration_hash']))
            if result.get('status')=='active':
                status=self.transport({'action':'read'})
                if not status.get('activation_verified') or status['hash']!=result['hash']:
                    raise RuntimeError('Activation receipt does not match current Victim rule')
                self.cache(status)
        except Exception as exc:
            result={'status':'unknown','error':str(exc)[:1500],'note':'Read Victim status before any new apply; no automatic retry.'}
        with closing(sqlite3.connect(self.path)) as db,db:
            db.execute('UPDATE rule_drafts SET status=?,result=? WHERE id=?',(result['status'],encode(result),values['id']))
        return result

    def restore(self,values):
        if not isinstance(values,dict) or set(values)!={'expected_hash','backup_id'}: raise ValueError('Restore a known backup against the current rule hash.')
        result=self.transport(dict(action='restore',**values))
        self.cache(self.transport({'action':'read'}))
        return result
