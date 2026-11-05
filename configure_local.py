"""Create absent local lab files from public examples. No network or VM actions."""
from datetime import datetime,timezone
import argparse
import json
from pathlib import Path
from experiment_store import ExperimentStore

ROOT=Path(__file__).resolve().parent


def configure(root=ROOT):
    root=Path(root).resolve();created=[]
    files={'live.ssh.example.json':'live.ssh.local.json',
           'runtime.ssh.live.example.json':'runtime.ssh.live.local.json',
           'response.example.json':'response.local.json'}
    for source,destination in files.items():
        path=root/destination
        if path.exists():continue
        value=json.loads((root/'config'/source).read_text())
        if destination=='response.local.json':value['review_notifications_enabled_after']=datetime.now(timezone.utc).isoformat()
        with path.open('x') as output:output.write(json.dumps(value,indent=2)+'\n')
        created.append(destination)
    registry=root/'plans/dashboard-plans.json';registry.parent.mkdir(exist_ok=True)
    if not registry.exists():
        with registry.open('x') as output:output.write('[]\n')
        created.append(str(registry.relative_to(root)))
    # Seed only a brand-new store; existing prompts, settings and results stay intact.
    if not (root/'lab-experiments.sqlite3').exists():
        store=ExperimentStore(root)
        try:
            current=store.state()['active']
            saved=store.save_prompt(dict(text=(root/'prompts/current.txt').read_text(),label='Final SSH lab instruction'))
            store.activate(dict(id=saved['id'],expected_active=current['id']))
        finally:store.close()
        created.append('lab-experiments.sqlite3')
    return {'created':created,'note':'Existing local files preserved. Examples default to dry run. No credentials, traffic or firewall changes.'}


if __name__=='__main__':
    argparse.ArgumentParser(description=__doc__).parse_args()
    print(json.dumps(configure(),indent=2))
