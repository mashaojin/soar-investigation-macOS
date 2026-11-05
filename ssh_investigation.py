"""Bounded SSH evidence bundles; never connects to a VM or response executor."""
import hashlib
import json
from analyst import validate_report
from ssh_scenarios import evidence_bundle


def compare_scope(auth, plan, checks):
    """Exact comparisons are policy facts, not a model-generated verdict."""
    if plan is None:
        return {'plan_available': False, 'coverage': auth.get('coverage'),
                'note': 'No plan found; assess authentication evidence, not absence alone.'}
    observed=set(auth['failed_accounts'])|set(auth.get('successful_accounts',{}))
    accounts = sorted(observed - set(plan['allowed_accounts']))
    return {'plan_available': True, 'plan_checks': checks,
            'unexpected_accounts': accounts,
            'observed_accounts': sorted(observed),
            'permitted_accounts': sorted(plan['allowed_accounts']),
            'observed_failed_attempts': auth['failed_password_count'],
            'maximum_failed_attempts': plan['maximum_failed_attempts'],
            'attempt_limit_exceeded': auth['failed_password_count'] > plan['maximum_failed_attempts'],
            'successful_logins': auth['successful_login_count'],
            'coverage': auth.get('coverage')}


def build_job(path):
    bundle = evidence_bundle(path)
    return build_bundle_job(bundle)


def build_bundle_job(bundle):
    # Opaque identifiers prevent scenario names from leaking evaluation labels.
    incident = dict(bundle['incident'])
    incident['id'] = hashlib.sha256(json.dumps(incident, sort_keys=True).encode()).hexdigest()[:16]
    auth = dict(bundle['authentication'])
    auth['evidence_id'] = incident['id'] + '-auth'
    investigation = {'kind': 'ssh', 'incident_id': incident['id'],
                     'authentication': auth,
                     'plan_evidence': {'plan': bundle['plan'], 'checks': bundle['plan_checks'],
                      'scope_comparison': compare_scope(auth, bundle['plan'], bundle['plan_checks'])}}
    prompt = 'Python-prepared SSH evidence: ' + json.dumps(incident, sort_keys=True)
    return prompt, investigation


def validate_investigation(envelope, investigation=None):
    report = validate_report(envelope['text'])
    if report['verdict'] != 'INSUFFICIENT_EVIDENCE' and set(envelope.get('tools_used', [])) != {
            'get_ssh_auth_summary', 'get_approved_test_plan'}:
        raise ValueError('Conclusive SSH report requires authentication and plan evidence')
    if (investigation is not None and report['verdict'] != 'INSUFFICIENT_EVIDENCE'
            and investigation['authentication'].get('coverage') not in ('complete_for_fixture', 'observed_window')):
        raise ValueError('Manual review: incomplete authentication coverage')
    if (investigation is not None and report['verdict'] != 'INSUFFICIENT_EVIDENCE'
            and investigation['authentication'].get('failed_password_count',0) == 0
            and investigation['authentication'].get('successful_login_count',0) == 0):
        raise ValueError('Manual review: no authentication outcomes were observed')
    if report['verdict'] == 'BENIGN' and investigation is not None:
        auth = investigation['authentication']
        evidence = investigation['plan_evidence']
        plan = evidence['plan']
        if (not plan or not all(evidence['checks'].values())
                or auth.get('coverage') not in ('complete_for_fixture', 'observed_window')
                or set(auth['failed_accounts']) - set(plan['allowed_accounts'])
                or auth['failed_password_count'] > plan['maximum_failed_attempts']
                or auth['successful_login_count'] != 0):
            raise ValueError('Manual review: BENIGN contradicts approved scope or evidence coverage')
    return report
