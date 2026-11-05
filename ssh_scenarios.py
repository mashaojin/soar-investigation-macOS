"""Offline SSH scenario contracts. Expectations are test labels, never AI output."""
import argparse
from datetime import datetime
import ipaddress
import json
from pathlib import Path

ROOT = Path(__file__).parent / 'fixtures' / 'ssh'


def timestamp(value):
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('Timezone required')
    return result


def plan_checks(incident, plan):
    """Deterministic scope checks; matching is not a benign verdict."""
    start, end = timestamp(incident['start']), timestamp(incident['end'])
    if end < start:
        raise ValueError('Invalid incident interval')
    if not plan:
        return {'plan_available': False}
    pstart, pend = timestamp(plan['start']), timestamp(plan['end'])
    if pend <= pstart:
        raise ValueError('Invalid plan interval')
    return {
        'plan_available': True,
        'approved': plan['approval_status'] == 'approved',
        'source_matches': incident['source_ip'] in plan['source_ips'],
        'target_matches': incident['target_ip'] == plan['target_ip'],
        'service_matches': incident['target_port'] == plan['target_port'],
        'within_window': pstart <= start and end < pend,
    }


def load_scenario(path):
    case = json.loads(Path(path).read_text())
    if case['kind'] != 'synthetic_fixture':
        raise ValueError('Expected synthetic fixture')
    incident = case['incident']
    for key in ('source_ip', 'target_ip'):
        ipaddress.ip_address(incident[key])
    if incident['target_port'] != 22:
        raise ValueError('SSH only')
    checks = plan_checks(incident, case['plan'])
    auth = case['authentication']
    if auth['source_ip'] != incident['source_ip'] or auth['target_ip'] != incident['target_ip']:
        raise ValueError('Authentication evidence belongs to another source/target')
    if not (timestamp(auth['start']) <= timestamp(incident['start']) and
            timestamp(auth['end']) >= timestamp(incident['end'])):
        raise ValueError('Authentication evidence does not cover incident')
    for key in ('failed_password_count', 'successful_login_count'):
        if type(auth[key]) is not int or auth[key] < 0:
            raise ValueError('Invalid authentication count')
    if sum(auth['failed_accounts'].values()) != auth['failed_password_count']:
        raise ValueError('Account counts do not match total failures')
    return case, checks


def evidence_bundle(path):
    case, checks = load_scenario(path)
    # Ground-truth labels must never enter the analyst prompt/tool responses.
    return {'incident': case['incident'], 'authentication': case['authentication'],
            'plan': case['plan'], 'plan_checks': checks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    results = []
    for path in sorted(ROOT.glob('*.json')):
        case, checks = load_scenario(path)
        results.append({'scenario': case['id'], 'kind': case['kind'],
                        'contract_valid': True, 'plan_checks': checks,
                        'expected_disposition': case['expected']['disposition']})
    if len(results) != 3:
        raise ValueError('Expected exactly three scenarios')
    receipt = {'verification': 'fixture contracts only; no AI inference or live traffic',
               'model_calls': 0, 'telegram_messages': 0, 'firewall_actions': 0,
               'scenarios': results}
    encoded = json.dumps(receipt, indent=2) + '\n'
    if args.output:
        args.output.write_text(encoded)
    print(encoded)


if __name__ == '__main__':
    main()
