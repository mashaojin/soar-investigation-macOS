"""Actual base-model assessment of synthetic fixtures; no lab/Telegram/firewall IO."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
from ollama_analyst import assessment_payload, make_prompt, ollama_report, validate_assessment
from ssh_investigation import build_job
from ssh_scenarios import ROOT, load_scenario
from advisory_report import assessment_label, validate as validate_advisory
from attack_knowledge import retrieve
from experiment_store import encode, sha


def compare_retrieval(payload, job, runner):
    knowledge = retrieve(payload)
    if not knowledge:
        raise ValueError('No relevant ATT&CK note for this fixture')
    settings = {'investigation': job, '_advisory_report': True}
    comparison = {'evidence_hash': sha(encode(payload)), 'arms': []}
    for name, context in (('without_retrieval', {}), ('with_retrieval', knowledge)):
        prompt = make_prompt(payload, advisory=True, knowledge=context)
        arm = {'name': name, 'prompt_hash': sha(prompt)}
        try:
            envelope = runner(prompt, settings)
            arm['metadata'] = {key: value for key, value in envelope.items() if key != 'text'}
            arm['raw_report'] = envelope['text']
            arm['report'] = validate_advisory(envelope['text'], payload, knowledge=context)
            arm['assessment'] = assessment_label(arm['report'])
        except (ValueError, KeyError, TypeError, OSError, RuntimeError) as exc:
            arm['error'] = str(exc)[:1500]
        comparison['arms'].append(arm)
    return comparison


def run(output, fixtures=ROOT, *, retrieval=False):
    receipt={'started_at':datetime.now(timezone.utc).isoformat(),
             'mode':'synthetic_fixture_retrieval_comparison' if retrieval else 'synthetic_fixture_actual_base_model','model':'gemma4:e4b',
             'telegram_messages':0,'firewall_actions':0,'attacks_launched':0,'results':[],'passed':False}
    for path in sorted(fixtures.glob('*.json')):
        case,_=load_scenario(path)
        _,job=build_job(path)
        payload=assessment_payload({'signature_id':9001001,'source_ip':case['incident']['source_ip'],
             'destination_ip':case['incident']['target_ip'],'destination_port':22,
             'window_start':case['incident']['start'],'alert_count':case['incident']['alert_count']},job)
        row={'scenario':case['id'],'assessment_data':payload,'investigation':job,'passed':False}
        try:
            row['expected_verdict']=case['expected'].get('verdict','BENIGN' if case['id']=='approved_test' else 'SUSPICIOUS')
            if retrieval:
                row['comparison'] = compare_retrieval(payload, job, ollama_report)
                baseline, candidate = row['comparison']['arms']
                row['passed'] = (baseline.get('assessment') == candidate.get('assessment') == row['expected_verdict']
                                 and bool(candidate.get('report', {}).get('knowledge_refs')))
            else:
                prompt=make_prompt(payload)
                envelope=ollama_report(prompt,{'investigation':job})
                row['metadata']={k:v for k,v in envelope.items() if k!='text'}
                row['raw_report']=envelope['text']
                row['report']=validate_assessment(envelope['text'],payload,job)
                row['passed']=row['report']['verdict']==row['expected_verdict']
        except Exception as exc: row['error']=str(exc)[:3000]
        receipt['results'].append(row)
        output.write_text(json.dumps(receipt,indent=2)+'\n')
        print(json.dumps({k:row.get(k) for k in ['scenario','passed','report','comparison','error']}),flush=True)
    receipt['passed']=len(receipt['results'])==3 and all(r['passed'] for r in receipt['results'])
    output.write_text(json.dumps(receipt,indent=2)+'\n')
    return receipt['passed']

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compare-retrieval', action='store_true', help='Run matched advisory A/B calls on all three fixtures')
    parser.add_argument('--output', type=Path)
    args=parser.parse_args()
    name = 'verification-attack-retrieval.json' if args.compare_retrieval else 'verification-gemma-direct.json'
    output = args.output or Path(__file__).with_name(name)
    raise SystemExit(0 if run(output, retrieval=args.compare_retrieval) else 1)
