"""Stage a reviewed installation package in Victim's home; never run its installer."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
from lab_config import load_profile
from ssh_transport import command
from windows_response import expected_receipt


def stage(root,package):
    root=Path(root);package=Path(package);lab=load_profile(root=root)
    if lab['platform']!='windows-hyperv':raise ValueError('Explicit Windows profile required')
    manifest=json.loads((package/'manifest.json').read_text())
    if any(manifest.get(k)!=v for k,v in expected_receipt(lab).items()):raise ValueError('Prepared package no longer matches current source/profile')
    names=set(manifest['files'])|{'install.py','manifest.json'}
    if not names<={'windows_response_helper.py','windows-response.json','sudoers','soc_rule_helper.py','rule-sudoers','install.py','manifest.json'}:
        raise ValueError('Unexpected installation files')
    files={name:(package/name).read_text() for name in names}
    for name,expected in dict(manifest['files'],**{'install.py':manifest['installer_hash']}).items():
        if hashlib.sha256(files[name].encode()).hexdigest()!=expected:raise ValueError('Prepared file changed')
    code='''import hashlib,json,os,pathlib,stat,sys
files=json.load(sys.stdin)
allowed={'windows_response_helper.py','windows-response.json','sudoers','soc_rule_helper.py','rule-sudoers','install.py','manifest.json'}
if not set(files)<=allowed:raise ValueError('Unexpected staged file')
folder=pathlib.Path.home()/'soc-windows-helpers';folder.mkdir(mode=0o700,exist_ok=True)
info=folder.lstat()
if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o022:raise ValueError('Unsafe staging directory')
hashes={}
for name,text in files.items():
 data=text.encode();path=folder/name
 if len(data)>65536 or path.is_symlink():raise ValueError('Unsafe staged file')
 if path.exists() and path.read_bytes()!=data:
  backup=path.with_name(name+'.'+hashlib.sha256(path.read_bytes()).hexdigest()+'.backup')
  if backup.is_symlink():raise ValueError('Unsafe backup')
  if not backup.exists():
   with backup.open('xb') as saved:saved.write(path.read_bytes())
 path.write_bytes(data);path.chmod(0o600);hashes[name]=hashlib.sha256(path.read_bytes()).hexdigest()
print(json.dumps(dict(staged=True,installed=False,executed=False,files=hashes)))
'''
    result=subprocess.run(command(lab,'victim','python3 -I -c '+shlex.quote(code)),input=json.dumps(files),capture_output=True,text=True,timeout=25,check=True)
    receipt=json.loads(result.stdout)
    if receipt['files']!={name:hashlib.sha256(text.encode()).hexdigest() for name,text in files.items()}:
        raise ValueError('Independent staged-file hashes differ')
    return receipt


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path(__file__).parent)
    parser.add_argument('--package',type=Path,required=True)
    args=parser.parse_args();print(json.dumps(stage(args.root,args.package),indent=2))
