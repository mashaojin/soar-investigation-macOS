"""Provision only the fixed rule helper via the lab's UTM guest agent."""
import base64
import hashlib
import json
from pathlib import Path
import secrets
import subprocess

from topology import UTM, load, ssh_target

ROOT=Path(__file__).resolve().parent


def main():
    topology = load()
    victim = topology["victim"]
    nonce = secrets.token_hex(16)
    source=(ROOT/'soc_rule_helper.py').read_bytes();expected=hashlib.sha256(source).hexdigest()
    payload=base64.b64encode(source).decode()
    code='''import base64,hashlib,json,os,pathlib,subprocess
addresses=json.loads(subprocess.check_output(['ip','-j','-4','address','show']))
if not any(info.get('local') == VICTIM_IP for interface in addresses for info in interface.get('addr_info', [])):
    raise ValueError('Rule helper must be installed on the configured Victim')
source=base64.b64decode(PAYLOAD)
helper=pathlib.Path('/usr/local/libexec/soc-rule-editor.py');helper.parent.mkdir(exist_ok=True)
if helper.is_symlink(): raise ValueError('Unsafe helper path')
helper.write_bytes(source);helper.chmod(0o755);os.chown(helper,0,0)
text=VICTIM_USER+' ALL=(root) NOPASSWD: /usr/bin/python3 /usr/local/libexec/soc-rule-editor.py\\n'
temporary=pathlib.Path('/etc/sudoers.d/.soc-rule-editor.tmp');temporary.write_text(text);temporary.chmod(0o440)
subprocess.run(['/usr/sbin/visudo','-cf',str(temporary)],check=True,capture_output=True)
temporary.replace('/etc/sudoers.d/soc-rule-editor')
receipt={'helper_sha256':hashlib.sha256(helper.read_bytes()).hexdigest(),'installed':True,'nonce':NONCE}
pathlib.Path('/tmp/soc-rule-editor-install.json').write_text(json.dumps(receipt))
'''.replace('PAYLOAD', repr(payload)).replace('VICTIM_IP', repr(victim['ip'])).replace(
        'VICTIM_USER', repr(victim['user'])).replace('NONCE', repr(nonce))
    subprocess.run([UTM,'exec',topology['victim']['name'],'--cmd','/usr/bin/python3','-c',code],check=True,capture_output=True,timeout=15)
    # Verify with an independent SSH read instead of assuming guest execution completed.
    receipt=subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=5','-o','StrictHostKeyChecking=yes',ssh_target(topology),'cat /tmp/soc-rule-editor-install.json'],capture_output=True,text=True,check=True,timeout=10)
    value=json.loads(receipt.stdout)
    if value.get('helper_sha256')!=expected or value.get('installed') is not True or value.get('nonce')!=nonce:
        raise ValueError('Helper installation was not verified')
    (ROOT/'rule-editor-enabled.json').write_text(json.dumps(value,indent=2)+'\n')
    print(json.dumps(value))


if __name__=='__main__': main()
