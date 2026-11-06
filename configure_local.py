"""Create absent local lab files from public examples. No network or VM actions."""
from datetime import datetime,timezone
import argparse
import json
from pathlib import Path
from experiment_store import ExperimentStore
from lab_config import load_profile,validate_profile,sources,protected,MAC

ROOT=Path(__file__).resolve().parent


def configure(root=ROOT, *, profile=None, lab=None):
    root=Path(root).resolve();created=[]
    local_lab=root/'lab.local.json'
    selected=validate_profile(lab) if lab is not None else load_profile(root=root) if local_lab.exists() else None
    if profile is not None:
        if profile not in ('macos-utm','windows-hyperv'):raise ValueError('Unknown platform profile')
        if selected is None:
            selected=validate_profile(json.loads((root/'config/lab.windows-hyperv.example.json').read_text())) if profile=='windows-hyperv' else validate_profile(MAC)
        if selected['platform']!=profile:raise ValueError('Existing platform differs; use a fresh runtime directory')
    if selected is not None:
        selected.pop('_path',None)
        if local_lab.exists():
            if validate_profile(json.loads(local_lab.read_text()))!=selected:
                raise ValueError('Existing lab profile differs; preserve state and review changes explicitly')
        else:
            state=('ssh-live.sqlite3','lab-experiments.sqlite3','plan-editor.sqlite3',
                   'live.ssh.local.json','runtime.ssh.live.local.json','response.local.json','plans/dashboard-plans.json')
            if selected['platform']=='windows-hyperv' and any((root/name).exists() for name in state):
                raise ValueError('Fresh Windows state required; existing operational files must not be reused or overwritten')
            with local_lab.open('x') as output:output.write(json.dumps(selected,indent=2)+'\n')
            created.append('lab.local.json')
    files={'live.ssh.example.json':'live.ssh.local.json',
           'runtime.ssh.live.example.json':'runtime.ssh.live.local.json',
           'response.example.json':'response.local.json'}
    for source,destination in files.items():
        path=root/destination
        if path.exists():continue
        value=json.loads((root/'config'/source).read_text())
        if selected is not None:
            value['lab_profile']='lab.local.json'
            if destination=='live.ssh.local.json':
                value.update(ssh_target=selected['victim']['user']+'@'+selected['victim']['ip'],
                             source_ips=sources(selected),destination_ip=selected['victim']['ip'])
            elif destination=='runtime.ssh.live.local.json':value['ollama']=selected['ollama']
            elif destination=='response.local.json':
                value.update(mode='dry_run',exclusive_polling_confirmed=False,victim_ip=selected['victim']['ip'],
                             allowed_attacker_ips=sources(selected),protected_ips=protected(selected),duration_seconds=60,
                             live_enabled_after=None)
                if selected['platform']=='windows-hyperv':value['credentials_source']=None
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
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile',choices=['macos-utm','windows-hyperv'])
    parser.add_argument('--lab-config',type=Path,help='Reviewed operator lab JSON; never model output')
    args=parser.parse_args()
    print(json.dumps(configure(profile=args.profile,lab=json.loads(args.lab_config.read_text()) if args.lab_config else None),indent=2))
