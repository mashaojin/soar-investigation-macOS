"""Provision only the fixed rule helper via the lab's UTM guest agent."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parent


def main():
    from lab_config import load_profile
    if load_profile(root=ROOT)['platform']!='macos-utm':
        raise ValueError('Windows helper requires separately reviewed SSH provisioning; UTM installer is Mac-only')
    source=(ROOT/'soc_rule_helper.py').read_bytes();expected=hashlib.sha256(source).hexdigest()
    payload=base64.b64encode(source).decode()
    code='''import base64,hashlib,json,os,pathlib,subprocess
source=base64.b64decode(PAYLOAD)
helper=pathlib.Path('/usr/local/libexec/soc-rule-editor.py');helper.parent.mkdir(exist_ok=True)
if helper.is_symlink(): raise ValueError('Unsafe helper path')
helper.write_bytes(source);helper.chmod(0o755);os.chown(helper,0,0)
text='victim ALL=(root) NOPASSWD: /usr/bin/python3 /usr/local/libexec/soc-rule-editor.py\\n'
temporary=pathlib.Path('/etc/sudoers.d/.soc-rule-editor.tmp');temporary.write_text(text);temporary.chmod(0o440)
subprocess.run(['/usr/sbin/visudo','-cf',str(temporary)],check=True,capture_output=True)
temporary.replace('/etc/sudoers.d/soc-rule-editor')
receipt={'helper_sha256':hashlib.sha256(helper.read_bytes()).hexdigest(),'installed':True}
pathlib.Path('/tmp/soc-rule-editor-install.json').write_text(json.dumps(receipt))
'''.replace('PAYLOAD',repr(payload))
    subprocess.run(['/Applications/UTM.app/Contents/MacOS/utmctl','exec','Victim','--cmd','/usr/bin/python3','-c',code],check=True,capture_output=True,timeout=15)
    # Verify with an independent SSH read instead of assuming guest execution completed.
    receipt=subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=5','victim@192.168.64.6','cat /tmp/soc-rule-editor-install.json'],capture_output=True,text=True,check=True,timeout=10)
    value=json.loads(receipt.stdout)
    if value.get('helper_sha256')!=expected or value.get('installed') is not True: raise ValueError('Helper installation was not verified')
    (ROOT/'rule-editor-enabled.json').write_text(json.dumps(value,indent=2)+'\n')
    print(json.dumps(value))


if __name__=='__main__': main()
