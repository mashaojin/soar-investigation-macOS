"""Read-only bounded journal query. Executed on Ubuntu via stdin, not installed."""
import base64
from collections import Counter
from datetime import datetime, timezone
import ipaddress
import json
import re
import subprocess
import sys

FAIL = re.compile(r'^Failed password for (?:invalid user )?(\S+) from (\S+) port \d+')
SUCCESS = re.compile(r'^Accepted (?:password|publickey|keyboard-interactive/pam) for (\S+) from (\S+) port \d+')


def validate_request(request):
    for name in ('source_ip', 'target_ip'):
        ipaddress.ip_address(request[name])
    start = datetime.fromisoformat(request['start'].replace('Z', '+00:00'))
    end = datetime.fromisoformat(request['end'].replace('Z', '+00:00'))
    if start.tzinfo is None or end.tzinfo is None or not 0 < (end-start).total_seconds() <= 600:
        raise ValueError('Require timezone-aware window of at most ten minutes')
    return start, end


def summarize(request, rows, limited=False):
    start, end = validate_request(request)
    failures, successes = Counter(), Counter()
    seen = set()
    unparsed = 0
    failure_times=[]
    drops=0; penalties=0; protection=[]
    for row in rows:
        cursor = row.get('__CURSOR')
        if cursor and cursor in seen:
            continue
        if cursor:
            seen.add(cursor)
        when = int(row['__REALTIME_TIMESTAMP']) / 1000000
        if not start.timestamp() <= when < end.timestamp():
            continue
        message = row.get('MESSAGE', '')
        if not isinstance(message, str):
            unparsed += 1
            continue
        match = FAIL.match(message)
        accepted = SUCCESS.match(message)
        if match or accepted:
            account, address = (match or accepted).groups()
            if address != request['source_ip']:
                continue
            if len(account) > 64 or len(failures.keys() | successes.keys() | {account}) > 32:
                limited = True
                continue
            (failures if match else successes)[account] += 1
            if match: failure_times.append(when)
        elif re.search(r'(?<![\w.:])' + re.escape(request['source_ip']) + r'(?![\w.:])', message):
            # Invalid-user/PAM messages are not additional failed-password events.
            unparsed += 1
            kind=None
            if re.match(r'^drop connection #\d+ from \['+re.escape(request['source_ip'])+r'\]:\d+ on ',message):
                drops+=1; kind='connection_drop'
            elif message.startswith('srclimit_penalise: '+request['source_ip']+'/') and 'activating ' in message and ' penalty' in message:
                penalties+=1; kind='penalty_activated'
            if kind and len(protection)<8:
                protection.append({'kind':kind,'timestamp':datetime.fromtimestamp(when,timezone.utc).isoformat()})
    return dict(request, evidence_source='ubuntu_ssh_journal',
                coverage='partial' if limited else 'journal_query_complete',
                coverage_note='Query completeness does not prove journal retention or absence of dropped events.',
                failed_password_count=sum(failures.values()), failed_accounts=dict(failures),
                successful_login_count=sum(successes.values()), successful_accounts=dict(successes),
                other_source_messages=unparsed, limited=limited,
                connection_drop_count=drops,penalty_event_count=penalties,protection_events=protection,
                failed_password_first=datetime.fromtimestamp(min(failure_times),timezone.utc).isoformat() if failure_times else None,
                failed_password_last=datetime.fromtimestamp(max(failure_times),timezone.utc).isoformat() if failure_times else None,
                failed_password_span_seconds=round(max(failure_times)-min(failure_times),3) if failure_times else None)


def collect(request):
    start, end = validate_request(request)
    command = ['journalctl', '-u', 'ssh.service', '--since', '@'+str(start.timestamp()),
               '--until', '@'+str(end.timestamp()), '-n', '1001', '--no-pager', '-o', 'json',
               '--output-fields=__CURSOR,__REALTIME_TIMESTAMP,MESSAGE,_UID']
    rows, total, limited = [], 0, False
    # Outer SSH caller enforces a hard wall-clock timeout. Per-line and total caps
    # prevent journal messages from exhausting memory or crossing to the host.
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as child:
        while True:
            line = child.stdout.readline(8193)
            if not line:
                break
            total += len(line)
            if len(line) > 8192 or total > 1048576 or len(rows) >= 1000:
                limited = True
                child.kill()
                break
            try:
                rows.append(json.loads(line))
            except (ValueError, TypeError):
                limited = True
        code = child.wait()
    if code and not limited:
        raise RuntimeError('SSH journal query failed')
    result = summarize(request, rows, limited)
    # A retained event before the window proves its start is not earlier than
    # every retained SSH record. This is an observation check, not proof of no loss.
    prior = subprocess.run(['journalctl','-u','ssh.service','--until','@'+str(start.timestamp()),
                            '-n','1','--no-pager','-o','json',
                            '--output-fields=__REALTIME_TIMESTAMP'],
                           capture_output=True, text=True, timeout=3)
    try:
        prior_rows = [json.loads(line) for line in prior.stdout.splitlines() if line.strip()]
        retained_start = prior.returncode == 0 and len(prior_rows) == 1 and int(prior_rows[0]['__REALTIME_TIMESTAMP']) / 1000000 <= start.timestamp()
    except (ValueError, KeyError, TypeError):
        retained_start = False
    elapsed = end.timestamp() <= datetime.now(timezone.utc).timestamp() - 2
    trusted = all(row.get('_UID') == '0' for row in rows)
    result['coverage_checks'] = {'retained_entry_before_start':retained_start,
                                 'window_elapsed':elapsed, 'root_service_records':trusted,
                                 'query_not_limited':not limited}
    if all(result['coverage_checks'].values()):
        result['coverage'] = 'observed_window'
    result['coverage_note'] = 'Counts describe retained SSH records for this window; no claim that logging cannot lose events.'
    return result


if __name__ == '__main__':
    request = json.loads(base64.b64decode(sys.argv[1]))
    print(json.dumps(collect(request), sort_keys=True))
