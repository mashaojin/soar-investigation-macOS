"""Copy demo client to precreated ~/soc-demo folders; never generates traffic."""
from pathlib import Path
import hashlib
import json
import subprocess
UTM='/Applications/UTM.app/Contents/MacOS/utmctl'
script=Path(__file__).with_name('ssh_demo_client.py').read_bytes()
results=[]
for machine,username in [('Kali Linux','kali'),('Trust-Client','trust-client')]:
    destination=f'/home/{username}/soc-demo/ssh_demo_client.py'
    push=subprocess.run([UTM,'file','push',machine,destination],input=script,capture_output=True,timeout=20)
    if push.returncode: raise RuntimeError('Push failed for '+machine)
    pull=subprocess.run([UTM,'file','pull',machine,destination],capture_output=True,timeout=20)
    if pull.returncode or pull.stdout!=script: raise RuntimeError('Copy verification failed for '+machine)
    results.append({'machine':machine,'path':destination,'sha256':hashlib.sha256(script).hexdigest(),'verified':True,'executed':False})
Path(__file__).with_name('verification-client-staging.json').write_text(json.dumps(results,indent=2)+'\n')
print(json.dumps(results,indent=2))
