"""Prepare current-incident evidence for the bounded SSH analyst."""
from datetime import datetime, timedelta
import hashlib
import json
from approved_plans import load_plans, select_plan
from ssh_evidence import collect_auth
from ssh_investigation import build_bundle_job
from ssh_scenarios import plan_checks, timestamp
from ssh_correlation import scope, recorded_plan, ready_at


def incident_context(incident_id, evidence):
    if evidence['signature_id'] != 9001001 or evidence['destination_port'] != 22:
        raise ValueError('Expected the SSH lab signature on TCP/22')
    start = timestamp(evidence['window_start'])
    saved = scope(evidence)
    end = timestamp(saved['end'])-timedelta(microseconds=1) if saved else start+timedelta(seconds=59)
    return {'id':incident_id,'source_ip':evidence['source_ip'],
            'target_ip':evidence['destination_ip'],'target_port':22,
            'start':start.isoformat(),'end':end.isoformat(),
            'signature_id':9001001,'alert_count':evidence.get('alert_count',1)}


def ready_after(evidence, plans_path):
    incident = incident_context('pending', evidence)
    plans = load_plans(plans_path)
    if scope(evidence):
        recorded_plan(evidence, plans)
        return ready_at(evidence)
    plan = select_plan(incident, plans)
    # Correlation ends at start+90s; wait another 30s for arrival and clock margin.
    return (timestamp(plan['end'])+timedelta(seconds=30) if plan else
            timestamp(incident['start'])+timedelta(seconds=120))


def prepare_live_job(incident_id, evidence, plans_path, collector=None, *, lab_profile=None):
    incident = incident_context(incident_id,evidence)
    plans = load_plans(plans_path)
    saved = scope(evidence)
    plan = recorded_plan(evidence, plans) if saved else select_plan(incident, plans)
    start = timestamp(incident['start'])
    # Approved activity is counted across the WHOLE plan, not per minute. The
    # analyst waits for its end + grace before claiming an incident revision.
    request = {'source_ip':incident['source_ip'],'target_ip':incident['target_ip'],
               'start':saved['evidence_start'] if saved else plan['start'] if plan else (start-timedelta(seconds=60)).isoformat(),
               'end':saved['end'] if saved else plan['end'] if plan else (start+timedelta(seconds=90)).isoformat()}
    auth = collector(request) if collector is not None else collect_auth(request,lab=lab_profile)
    if any(auth.get(k) != v for k,v in request.items()):
        raise ValueError('Authentication evidence attribution mismatch')
    if auth.get('coverage') not in ('journal_query_complete','partial','observed_window'):
        raise ValueError('Unexpected live coverage label; fixtures cannot be passed as live')
    if auth['coverage'] == 'observed_window' and not all(auth.get('coverage_checks',{}).get(key) is True
            for key in ('retained_entry_before_start','window_elapsed','root_service_records','query_not_limited')):
        raise ValueError('Observed coverage requires all independent checks')
    auth['counting_scope'] = 'entire_approved_plan' if plan else 'fixed_two_minute_correlation' if saved else 'incident_correlation_window'
    prompt, investigation = build_bundle_job({'incident':incident,'authentication':auth,
                      'plan':plan,'plan_checks':plan_checks(incident,plan)})
    investigation['origin'] = 'live_read_only'
    investigation['plan_snapshot_hash'] = hashlib.sha256(json.dumps(plans,sort_keys=True).encode()).hexdigest()
    return prompt, investigation
