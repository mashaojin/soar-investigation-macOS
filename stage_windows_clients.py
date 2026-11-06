"""Stage public manual-test inputs over verified SSH; never execute client traffic."""
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
from ssh_transport import command

ROOT=Path(__file__).resolve().parent


def stage(lab):
    known=subprocess.run(['ssh-keygen','-F',lab['victim']['ip'],'-f',str(Path(lab['ssh']['known_hosts_file']).expanduser())],capture_output=True,text=True,timeout=5,check=True)
    keys='\n'.join(line for line in known.stdout.splitlines() if line and not line.startswith('#'))+'\n'
    if not keys.strip():raise ValueError('Verified victim host key is missing')
    public=dict(lab);public.pop('_path',None)
    files={'ssh_demo_client.py':(ROOT/'ssh_demo_client.py').read_text(),
           'lab.local.json':json.dumps(public,indent=2)+'\n','known_hosts':keys}
    remote='''import hashlib,json,os,pathlib,stat,sys
files=json.load(sys.stdin)
if set(files)!={'ssh_demo_client.py','lab.local.json','known_hosts'}:raise ValueError('Unexpected staging files')
folder=pathlib.Path.home()/'soc-demo';folder.mkdir(mode=0o700,exist_ok=True)
info=folder.lstat()
if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o022:raise ValueError('Unsafe demo directory')
result={}
for name,text in files.items():
 data=text.encode();path=folder/name
 if len(data)>65536 or path.is_symlink():raise ValueError('Unsafe staging file')
 if path.exists() and path.read_bytes()!=data:
  backup=path.with_name(name+'.'+hashlib.sha256(path.read_bytes()).hexdigest()+'.backup')
  if backup.is_symlink():raise ValueError('Unsafe backup path')
  if not backup.exists():
   with backup.open('xb') as saved:saved.write(path.read_bytes())
 path.write_bytes(data);path.chmod(0o600)
 result[name]=hashlib.sha256(path.read_bytes()).hexdigest()
print(json.dumps(result))
'''
    results=[]
    for role in ('attacker','trust_client'):
        p=subprocess.run(command(lab,role,'python3 -c '+shlex.quote(remote)),input=json.dumps(files),capture_output=True,text=True,timeout=25,check=True)
        hashes=json.loads(p.stdout)
        if hashes!={name:hashlib.sha256(text.encode()).hexdigest() for name,text in files.items()}:raise ValueError('Client staging hash mismatch')
        results.append(dict(machine=lab[role]['vm'],verified=True,executed=False,files=hashes))
    return results
