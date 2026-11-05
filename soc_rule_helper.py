"""Install root-owned on Victim. Fixed-file Suricata SSH rule editor, JSON stdin only."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

RULE=Path('/etc/suricata/rules/ssh_bruteforce.rules')
CONFIG=Path('/etc/suricata/suricata.yaml')
STATE=Path('/var/lib/soc-rule-editor')
DEFAULT='alert tcp any any -> any 22 (msg:"ET SCAN Potential SSH Brute Force Attack"; flow:to_server; flags:S; threshold: type both, track by_src, count 5, seconds 30; classtype:attempted-admin; sid:9001001; rev:1;)\n'
PATTERN=re.compile(r'alert\s+tcp\s+any\s+any\s+->\s+any\s+22\s*\(\s*msg:\s*"([^"\\\n]{1,160})";\s*flow:\s*to_server;\s*flags:\s*S;\s*threshold:\s*type\s+both,\s*track\s+by_src,\s*count\s+(\d+),\s*seconds\s+(\d+);\s*classtype:\s*attempted-admin;\s*sid:\s*9001001;\s*rev:\s*(\d+);\s*\)')


def sha(value): return hashlib.sha256(value.encode()).hexdigest()


def parse_rule(text):
    if not isinstance(text,str) or len(text.encode())>2048: raise ValueError('One SSH lab rule, maximum 2048 bytes.')
    match=PATTERN.fullmatch(text.strip())
    if not match: raise ValueError('Use the SSH lab template. Only message, threshold count/seconds and revision may change; SID 9001001 and TCP/22 stay fixed.')
    msg,count,seconds,rev=match.groups();count,seconds,rev=map(int,(count,seconds,rev))
    if any(ord(c)<32 for c in msg) or not 1<=count<=100 or not 1<=seconds<=300 or not 1<=rev<=2147483647:
        raise ValueError('Count 1–100, seconds 1–300 and positive revision required.')
    return dict(message=msg,count=count,seconds=seconds,revision=rev)


def run(args,timeout=45):
    result=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
    if result.returncode: raise RuntimeError((result.stderr+'\n'+result.stdout)[-3000:])
    return result.stdout


def socket(command):
    output=run(['/usr/bin/suricatasc','-c',command],timeout=50)
    # suricatasc may precede JSON with a socket-connect message.
    result=json.loads(output[output.index('{'):])
    if result.get('return')!='OK': raise RuntimeError('Suricata command failed: '+str(result)[:1500])
    return result.get('message')


def atomic(path,text,mode=0o600):
    temporary=path.with_name(path.name+'.tmp')
    with temporary.open('w') as stream:
        stream.write(text);stream.flush();os.fsync(stream.fileno())
    temporary.chmod(mode);temporary.replace(path)


def trusted_rule():
    if RULE.is_symlink() or not RULE.is_file(): raise ValueError('Unsafe or missing fixed rule file')
    text=RULE.read_text();parse_rule(text)
    return text


def status():
    text=trusted_rule(); previous=None
    if (STATE/'last.json').exists(): previous=json.loads((STATE/'last.json').read_text())
    running=run(['/usr/bin/systemctl','is-active','suricata']).strip()=='active'
    stats=socket('ruleset-stats')
    return dict(text=text,hash=sha(text),fields=parse_rule(text),service_running=running,engine_stats=stats,
                observed_at=time.time(),last_activation=previous,
                activation_verified=bool(previous and previous.get('status')=='active' and previous.get('hash')==sha(text)))


def candidate_test(text,folder):
    parse_rule(text)
    candidate=folder/'candidate.rules';candidate.write_text(text)
    # Override only the fixed SSH rule path; retain all other configured rules.
    config=CONFIG.read_text()
    if config.count('  - ssh_bruteforce.rules')!=1:
        raise ValueError('Expected one fixed SSH rule reference in Suricata configuration')
    candidate_config=folder/'candidate.yaml'
    candidate_config.write_text(config.replace('  - ssh_bruteforce.rules','  - '+str(candidate)))
    run(['/usr/bin/suricata','-T','--init-errors-fatal','-c',str(candidate_config),'-l',str(folder)])
    return dict(valid=True,candidate_hash=sha(text),configuration_hash=sha(config))


def handle(request):
    if not isinstance(request,dict) or request.get('action') not in ('read','validate','apply','restore'):
        raise ValueError('Unsupported fixed rule operation')
    action=request['action']
    if action=='read':
        if set(request)!={'action'}: raise ValueError('Unexpected read fields')
        return status()
    if action=='restore':
        if set(request)!={'action','expected_hash','backup_id'} or not re.fullmatch('[a-f0-9]{24}',request['backup_id']):
            raise ValueError('Choose a saved backup and current hash')
        original=(STATE/(request['backup_id']+'.rules')).read_text()
        text=re.sub(r'rev:\s*\d+;', 'rev:'+str(parse_rule(trusted_rule())['revision']+1)+';',original)
    else:
        expected={'action','text','expected_hash'}
        if action=='apply': expected|={'configuration_hash'}
        if set(request)!=expected: raise ValueError('Unexpected rule request fields')
        text=request['text']
    before=trusted_rule()
    if sha(before)!=request['expected_hash']: raise ValueError('Victim rule changed. Read and validate again.')
    fields=parse_rule(text)
    if text!=before and fields['revision']<=parse_rule(before)['revision']:
        raise ValueError('Increase the rule revision for a changed rule.')
    with tempfile.TemporaryDirectory(prefix='validation-',dir=STATE) as work:
        test=candidate_test(text,Path(work))
    if action=='validate': return dict(test,base_hash=sha(before),fields=fields)
    if action=='apply' and request['configuration_hash']!=test['configuration_hash']:
        raise ValueError('Suricata configuration changed. Validate again.')
    identifier=os.urandom(12).hex();backup=STATE/(identifier+'.rules');backup.write_text(before);backup.chmod(0o600)
    receipt=dict(id=identifier,backup_id=identifier,previous_hash=sha(before),hash=sha(text),revision=fields['revision'],started_at=time.time())
    try:
        atomic(RULE,text,0o644)
        run(['/usr/bin/suricata','-T','--init-errors-fatal','-c',str(CONFIG),'-l',str(STATE)])
        socket('reload-rules')  # Blocking reload waits until the detection engine is swapped.
        stats=socket('ruleset-stats')
        if any(s.get('rules_failed',0)!=0 for s in (stats if isinstance(stats,list) else [stats]) if isinstance(s,dict)):
            raise RuntimeError('Engine reports failed rules')
        if run(['/usr/bin/systemctl','is-active','suricata']).strip()!='active': raise RuntimeError('Suricata is not active')
        receipt.update(status='active',activated_at=time.time(),engine_stats=stats)
    except Exception as exc:
        atomic(RULE,before,0o644)
        try:
            socket('reload-rules');receipt.update(status='rolled_back',error=str(exc)[:1500])
        except Exception as rollback:
            receipt.update(status='recovery_required',error=str(exc)[:1000],rollback_error=str(rollback)[:1000])
        atomic(STATE/'last.json',json.dumps(receipt))
        return receipt
    atomic(STATE/'last.json',json.dumps(receipt))
    atomic(STATE/(identifier+'.json'),json.dumps(receipt))
    return dict(receipt,text=text)


def main():
    if os.geteuid()!=0: raise ValueError('Restricted helper requires root')
    STATE.mkdir(mode=0o700,exist_ok=True)
    if STATE.is_symlink() or STATE.stat().st_uid!=0 or STATE.stat().st_mode&0o077: raise ValueError('Unsafe helper state directory')
    request=json.loads(sys.stdin.buffer.read(4097))
    with (STATE/'editor.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        try: result=dict(ok=True,result=handle(request))
        except Exception as exc: result=dict(ok=False,error=type(exc).__name__+': '+str(exc)[:3000])
    print(json.dumps(result))


if __name__=='__main__': main()
