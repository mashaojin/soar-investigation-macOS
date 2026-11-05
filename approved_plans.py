"""Validated local authorization records. Drafts never authorize an incident."""
import ipaddress
import json
from pathlib import Path
from ssh_scenarios import timestamp, plan_checks

REQUIRED = {'id','approval_status','owner','source_ips','target_ip','target_port',
            'start','end','allowed_accounts','maximum_failed_attempts','scope','stop_conditions'}


def validate_plan(plan):
    if not isinstance(plan, dict) or not REQUIRED <= plan.keys():
        raise ValueError('Missing plan fields')
    for field in ('id','owner','scope'):
        if not isinstance(plan[field], str) or not 1 <= len(plan[field]) <= 2000:
            raise ValueError('Invalid plan text')
    if plan['approval_status'] not in ('draft','approved','revoked'):
        raise ValueError('Invalid approval status')
    for field in ('source_ips','allowed_accounts','stop_conditions'):
        values = plan[field]
        if not isinstance(values,list) or not 1 <= len(values) <= 32 or any(
                not isinstance(v,str) or not 1 <= len(v) <= 200 for v in values):
            raise ValueError('Invalid plan list')
    for address in plan['source_ips'] + [plan['target_ip']]:
        ipaddress.ip_address(address)
    if type(plan['target_port']) is not int or plan['target_port'] != 22:
        raise ValueError('SSH port 22 only')
    if type(plan['maximum_failed_attempts']) is not int or not 1 <= plan['maximum_failed_attempts'] <= 100:
        raise ValueError('Invalid failed-attempt limit')
    if timestamp(plan['end']) <= timestamp(plan['start']):
        raise ValueError('Invalid plan window')
    if plan['approval_status'] == 'approved':
        if (timestamp(plan['end']) - timestamp(plan['start'])).total_seconds() > 600:
            raise ValueError('Approved demo windows are limited to ten minutes')
        if not isinstance(plan.get('approved_by'),str) or not plan['approved_by'].strip():
            raise ValueError('Approved plan requires approver identity')
        if timestamp(plan['approved_at']) > timestamp(plan['start']):
            raise ValueError('Approval must precede test window')
    return plan


def load_plans(path, *, allow_legacy_word=False):
    path = Path(path)
    if path.stat().st_size > 65536:
        raise ValueError('Plan file exceeds 64KB')
    plans = json.loads(path.read_text())
    if not isinstance(plans,list) or len(plans) > 32:
        raise ValueError('Expected at most 32 plans')
    resolved = []
    for plan in plans:
        if isinstance(plan, dict) and 'document' in plan:
            if not allow_legacy_word:
                raise ValueError('Legacy Word registry requires explicit migration; it is not active authorization')
            if plan.get('revoked_at'):
                continue
            # A Word file is the source; the registry stores approval only.
            from plan_document import import_plan
            document = Path(plan['document'])
            if not document.is_absolute(): document = path.parent / document
            extracted = import_plan(document)
            if extracted['source_sha256'] != plan.get('sha256'):
                raise ValueError('Word plan changed since approval: '+document.name)
            extracted.update(approval_status='approved', approved_by=plan.get('approved_by'),
                             approved_at=plan.get('approved_at'))
            plan = extracted
        validate_plan(plan)
        resolved.append(plan)
    plans = resolved
    if len({p['id'] for p in plans}) != len(plans):
        raise ValueError('Duplicate plan identifiers')
    return plans


def select_plan(incident, plans):
    eligible = [p for p in plans if p['approval_status'] == 'approved'
                and all(plan_checks(incident,p).values())]
    if len(eligible) > 1:
        raise ValueError('Overlapping approved plans require manual review')
    # A nonmatch is not itself a malicious verdict.
    return eligible[0] if eligible else None
