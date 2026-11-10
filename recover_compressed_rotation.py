"""Explicit, audited retained-log recovery; never automatically reset a cursor."""
from contextlib import closing
from datetime import datetime, timezone
import base64
import fcntl
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
from live import collect_once, source_key

REMOTE = r'''
import base64,gzip,hashlib,json,os,sys
request=json.load(sys.stdin)
path=request['path'];cursor=request['cursor']
compressed=path+'.1.gz'
if cursor['offset']<=0:raise ValueError('Expected an existing positive cursor')
active=os.stat(path)
if f'{active.st_dev}:{active.st_ino}'!=cursor['identity'] or active.st_size>=cursor['offset']:
 raise ValueError('Expected confirmed copytruncate with the same active identity')
old=os.stat(compressed)
if old.st_mtime>active.st_mtime:raise ValueError('Rotation is newer than active log')
remaining=cursor['offset'];tail=b''
with gzip.open(compressed,'rb') as stream:
 while remaining:
  block=stream.read(min(1048576,remaining))
  if not block:raise ValueError('Compressed log shorter than saved cursor')
  remaining-=len(block);tail=(tail+block)[-256:]
 if hashlib.sha256(tail).hexdigest()!=cursor['anchor']:
  raise ValueError('Compressed log does not match saved cursor anchor')
 if not tail.endswith(b'\n'):raise ValueError('Saved cursor is not a complete-line boundary')
 unread=stream.read(1048577)
 if len(unread)>1048576:raise ValueError('Unread rotation tail exceeds one-MB recovery limit')
 # Reading to EOF verifies gzip CRC/trailer, including the retained prefix.
 if stream.read(1):raise ValueError('Unread recovery budget exceeded')
if unread and not unread.endswith(b'\n'):raise ValueError('Rotated tail has incomplete JSON line')
if any(not isinstance(json.loads(line),dict) for line in unread.splitlines()):raise ValueError('Invalid JSON event in rotated tail')
if os.stat(compressed).st_mtime_ns!=old.st_mtime_ns:raise ValueError('Rotation changed during inspection')
active_after=os.stat(path)
if (active_after.st_dev,active_after.st_ino)!=(active.st_dev,active.st_ino):raise ValueError('Active log rotated during recovery')
print(json.dumps({'old_cursor':cursor,'compressed_path':compressed,'anchor_verified':True,
 'gzip_eof_verified':True,'tail_base64':base64.b64encode(unread).decode(),
 'tail_sha256':hashlib.sha256(unread).hexdigest(),
 'cursor':{'identity':f'{active.st_dev}:{active.st_ino}','offset':0,'anchor':hashlib.sha256(b'').hexdigest()}}))
'''


def recovery_batch(proof, expected):
    if proof.get('old_cursor')!=expected or proof.get('anchor_verified') is not True or proof.get('gzip_eof_verified') is not True:
        raise ValueError('Recovery proof does not verify the saved cursor')
    tail=base64.b64decode(proof['tail_base64'],validate=True)
    if len(tail)>1048576 or hashlib.sha256(tail).hexdigest()!=proof['tail_sha256']:
        raise ValueError('Recovery tail exceeds budget or digest does not match')
    if tail and not tail.endswith(b'\n'):raise ValueError('Incomplete recovery line')
    lines=tail.splitlines(keepends=True)
    if any(not isinstance(json.loads(line),dict) for line in lines):raise ValueError('Invalid recovery event')
    cursor=proof['cursor']
    if cursor!={'identity':expected['identity'],'offset':0,'anchor':hashlib.sha256(b'').hexdigest()}:
        raise ValueError('Invalid recovery destination cursor')
    return {'lines':[base64.b64encode(line).decode() for line in lines],
            'cursor':cursor,'has_more':True,'rotation_advanced':True,'baseline_skipped_bytes':0},tail


def recover(root):
    root=Path(root).resolve();db_path=root/'ssh-live.sqlite3'
    from topology import collector_config
    config=collector_config(json.loads((root/'live.ssh.local.json').read_text()), root)
    with open(str(db_path)+'.monitor.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with closing(sqlite3.connect(db_path)) as db:
            old=json.loads(db.execute('SELECT cursor FROM remote_checkpoints WHERE source=?',(source_key(config),)).fetchone()[0])
        request=json.dumps({'path':config['log_path'],'cursor':old})
        script=REMOTE.replace('request=json.load(sys.stdin)','request=json.loads('+repr(request)+')')
        result=subprocess.run(['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5',config['ssh_target'],'python3 -'],
                              input=script,text=True,capture_output=True,timeout=25)
        if result.returncode:raise RuntimeError(result.stderr[-1500:])
        proof=json.loads(result.stdout);batch,tail=recovery_batch(proof,old)
        stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        archive=root/'recovery-audit'/stamp;archive.mkdir(parents=True,exist_ok=False)
        (archive/'retained-tail.jsonl').write_bytes(tail)
        (archive/'proof.json').write_text(json.dumps(proof,indent=2)+'\n')
        with closing(sqlite3.connect(db_path)) as source,closing(sqlite3.connect(archive/'before.sqlite3')) as backup:
            source.backup(backup)
        audit={'archive':str(archive),'old_cursor':old,'new_cursor':batch['cursor'],
               'compressed_path':proof['compressed_path'],'tail_bytes':len(tail),
               'tail_sha256':proof['tail_sha256'],'anchor_verified':True,'gzip_eof_verified':True,
               'note':'Recovered retained rotation tail, then resume active file from byte zero; no claim logging never lost events.'}
        with closing(sqlite3.connect(db_path)) as db,db:
            db.execute('INSERT INTO remote_audit(source,kind,detail) VALUES(?,?,?)',
                       (source_key(config),'retained_rotation_recovery_intent',json.dumps(audit)))
        def reader(_,cursor):
            if cursor!=old:raise ValueError('Collector cursor changed during recovery')
            return batch
        outcome=collect_once(config,db_path,reader=reader)
        audit['outcome']=outcome
        with closing(sqlite3.connect(db_path)) as db,db:
            db.execute('INSERT INTO remote_audit(source,kind,detail) VALUES(?,?,?)',
                       (source_key(config),'retained_rotation_recovered',json.dumps(audit)))
        (root/'verification-rotation-recovery.json').write_text(json.dumps(audit,indent=2)+'\n')
        return audit

if __name__=='__main__':print(json.dumps(recover(Path(__file__).resolve().parent),indent=2))
