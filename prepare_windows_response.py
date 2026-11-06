"""Prepare reviewable helper installation files; never installs or grants access."""
import argparse
import hashlib
import json
from pathlib import Path

from lab_config import load_profile
from windows_response import helper_config, expected_receipt


INSTALL = '''#!/usr/bin/python3
"""One-time reviewed installation; no firewall operations or service activation."""
import argparse, hashlib, json, os, pathlib, re, stat, subprocess, tempfile
ROOT=pathlib.Path(__file__).resolve().parent
EXPECTED=__EXPECTED__
USER=__USER__
def content(name):
    data=(ROOT/name).read_bytes()
    if hashlib.sha256(data).hexdigest()!=EXPECTED[name]:raise ValueError('Package changed: '+name)
    return data
def safe_parent(path):
    path.mkdir(parents=True,exist_ok=True,mode=0o755)
    for parent in [path,*path.parents]:
        info=parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise ValueError('Unsafe destination parent: '+str(parent))
def install(path,data,mode):
    safe_parent(path.parent)
    if path.exists() or path.is_symlink():
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or path.read_bytes()!=data:
            raise ValueError('Existing installation differs; review separately: '+str(path))
        return
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as file:file.write(data)
    os.chmod(path,mode)
parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--apply',action='store_true');args=parser.parse_args()
files={name:content(name) for name in EXPECTED}
if not args.apply:
    print(json.dumps(dict(status='prepared',files=EXPECTED,firewall_changes=False,new_sudo_access=True),indent=2));raise SystemExit(0)
if os.geteuid()!=0:raise ValueError('Run manually with sudo only after reviewing the exact package')
for binary in ['/usr/sbin/nft','/usr/sbin/ip','/usr/bin/systemd-run','/usr/bin/systemctl','/usr/sbin/visudo']:
    if not pathlib.Path(binary).is_file():raise ValueError('Missing existing dependency: '+binary)
with tempfile.NamedTemporaryFile() as file:
    file.write(files['sudoers']);file.flush()
    subprocess.run(['/usr/sbin/visudo','-cf',file.name],check=True,timeout=10)
install(pathlib.Path('/etc/soc-pipeline/windows-response.json'),files['windows-response.json'],0o600)
install(pathlib.Path('/usr/local/libexec/soc-windows-response.py'),files['windows_response_helper.py'],0o755)
install(pathlib.Path('/etc/sudoers.d/soc-windows-response'),files['sudoers'],0o440)
if 'soc_rule_helper.py' in files:
    with tempfile.NamedTemporaryFile() as file:
        file.write(files['rule-sudoers']);file.flush()
        subprocess.run(['/usr/sbin/visudo','-cf',file.name],check=True,timeout=10)
    install(pathlib.Path('/usr/local/libexec/soc-rule-editor.py'),files['soc_rule_helper.py'],0o755)
    install(pathlib.Path('/etc/sudoers.d/soc-rule-editor-windows'),files['rule-sudoers'],0o440)
print(json.dumps(dict(status='installed',firewall_changes=False,new_sudo_access=True,operator=USER)))
'''


def prepare(root, output, with_rule_editor=False):
    root=Path(root);output=Path(output)
    lab=load_profile(root=root)
    if lab['platform']!='windows-hyperv':raise ValueError('Explicit Windows profile required')
    if output.exists():raise ValueError('Use a new output directory; preserve previous prepared package')
    config=helper_config(lab)
    helper=(Path(__file__).parent/'windows_response_helper.py').read_bytes()
    user=lab['victim']['user']
    sudoers=(f'# Reviewed fixed operations only; helper validates all arguments and scope.\n'
             f'{user} ALL=(root) NOPASSWD: /usr/local/libexec/soc-windows-response.py inspect, '
             '/usr/local/libexec/soc-windows-response.py read *, '
             '/usr/local/libexec/soc-windows-response.py apply *, '
             '/usr/local/libexec/soc-windows-response.py rollback *\n').encode()
    files={'windows_response_helper.py':helper,'windows-response.json':(json.dumps(config,indent=2)+'\n').encode(),'sudoers':sudoers}
    if with_rule_editor:
        files['soc_rule_helper.py']=(Path(__file__).parent/'soc_rule_helper.py').read_bytes()
        files['rule-sudoers']=(f'{user} ALL=(root) NOPASSWD: /usr/bin/python3 -I /usr/local/libexec/soc-rule-editor.py\n').encode()
    hashes={name:hashlib.sha256(data).hexdigest() for name,data in files.items()}
    output.mkdir(parents=True)
    for name,data in files.items():(output/name).write_bytes(data)
    installer=INSTALL.replace('__EXPECTED__',repr(hashes)).replace('__USER__',repr(user))
    (output/'install.py').write_text(installer)
    receipt=dict(expected_receipt(lab),provisioned=False,victim_ip=lab['victim']['ip'],files=hashes,
                 installer_hash=hashlib.sha256(installer.encode()).hexdigest(),firewall_changes=False)
    (output/'manifest.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return receipt


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path(__file__).parent)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--with-rule-editor',action='store_true',help='Also prepare the existing fixed Suricata rule editor; grants are separate from installation approval')
    args=parser.parse_args();print(json.dumps(prepare(args.root,args.output,args.with_rule_editor),indent=2))
