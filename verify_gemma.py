"""Actual base-model assessment of synthetic fixtures; no lab/Telegram/firewall IO."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
from ollama_analyst import assessment_payload, make_prompt, ollama_report, validate_assessment
from ssh_investigation import build_job
from ssh_scenarios import ROOT, load_scenario


def run(output, fixtures=ROOT):
    receipt={'started_at':datetime.now(timezone.utc).isoformat(),
             'mode':'synthetic_fixture_actual_base_model','model':'gemma4:e4b',
             'telegram_messages':0,'firewall_actions':0,'attacks_launched':0,'results':[],'passed':False}
    for path in sorted(fixtures.glob('*.json')):
        case,_=load_scenario(path)
        _,job=build_job(path)
        payload=assessment_payload({'signature_id':9001001,'source_ip':case['incident']['source_ip'],
             'destination_ip':case['incident']['target_ip'],'destination_port':22,
             'window_start':case['incident']['start'],'alert_count':case['incident']['alert_count']},job)
        row={'scenario':case['id'],'assessment_data':payload,'investigation':job,'passed':False}
        try:
            prompt=make_prompt(payload)
            envelope=ollama_report(prompt,{'investigation':job})
            row['metadata']={k:v for k,v in envelope.items() if k!='text'}
            row['raw_report']=envelope['text']
            row['report']=validate_assessment(envelope['text'],payload,job)
            row['expected_verdict']=case['expected'].get('verdict','BENIGN' if case['id']=='approved_test' else 'SUSPICIOUS')
            row['passed']=row['report']['verdict']==row['expected_verdict']
        except Exception as exc: row['error']=str(exc)[:3000]
        receipt['results'].append(row)
        output.write_text(json.dumps(receipt,indent=2)+'\n')
        print(json.dumps({k:row.get(k) for k in ['scenario','passed','report','error']}),flush=True)
    receipt['passed']=len(receipt['results'])==3 and all(r['passed'] for r in receipt['results'])
    output.write_text(json.dumps(receipt,indent=2)+'\n')
    return receipt['passed']

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=Path(__file__).with_name('verification-gemma-direct.json'))
    args=parser.parse_args()
    raise SystemExit(0 if run(args.output) else 1)
