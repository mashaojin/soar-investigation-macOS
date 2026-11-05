"""Exact fact checks; no rule chooses the model's security verdict."""
import re

VERSION='gemma_judgment_v2'
ACCOUNTS={'type':'array','maxItems':32,'uniqueItems':True,'items':{'type':'string','minLength':1,'maxLength':64}}
CLAIM_SCHEMA={'type':'object','additionalProperties':False,
    'required':['failed_password_count','successful_login_count','attempted_accounts','matching_plan',
                'unexpected_accounts','attempt_limit_exceeded','coverage','connection_drop_count','penalty_event_count'],
    'properties':{
        'failed_password_count':{'type':'integer','minimum':0},
        'successful_login_count':{'type':'integer','minimum':0},
        'attempted_accounts':ACCOUNTS,'matching_plan':{'type':'boolean'},'unexpected_accounts':ACCOUNTS,
        'attempt_limit_exceeded':{'type':['boolean','null']},'coverage':{'type':'string','maxLength':40},
        'connection_drop_count':{'type':'integer','minimum':0},'penalty_event_count':{'type':'integer','minimum':0}}}


def observed_claims(job):
    auth=job['authentication']; pe=job['plan_evidence']; plan=pe['plan']; findings=pe['scope_comparison'] if plan else {}
    accounts=sorted(set(auth['failed_accounts'])|set(auth.get('successful_accounts',{})))
    if plan:
        if sorted(findings['unexpected_accounts'])!=sorted(set(accounts)-set(plan['allowed_accounts'])) or findings['attempt_limit_exceeded']!=(auth['failed_password_count']>plan['maximum_failed_attempts']):
            raise ValueError('Recorded scope comparison contradicts authentication or plan facts')
    return dict(failed_password_count=auth['failed_password_count'],successful_login_count=auth['successful_login_count'],
                attempted_accounts=accounts,matching_plan=plan is not None,
                unexpected_accounts=findings['unexpected_accounts'] if plan else [],
                attempt_limit_exceeded=findings['attempt_limit_exceeded'] if plan else None,
                coverage=auth['coverage'],connection_drop_count=auth.get('connection_drop_count',0),
                penalty_event_count=auth.get('penalty_event_count',0))


def has_observations(auth):
    return any(auth.get(k,0)>0 for k in ('failed_password_count','successful_login_count','connection_drop_count','penalty_event_count'))


def validate_claims(claims,job):
    expected=observed_claims(job)
    if not isinstance(claims,dict) or set(claims)!=set(expected): raise ValueError('Missing or invalid structured fact claims')
    for key,want in expected.items():
        actual=claims[key]
        if isinstance(want,list):
            if not isinstance(actual,list) or any(not isinstance(a,str) for a in actual) or len(set(actual))!=len(actual) or sorted(actual)!=sorted(want):
                raise ValueError('Fact claim contradicts evidence: '+key)
        elif type(actual) is not type(want) or actual!=want:
            raise ValueError('Fact claim contradicts evidence: '+key)


def check_prose(reason,job):
    """Limited explicit contradictions, not a claim of complete prose verification."""
    auth=job['authentication']; plan=job['plan_evidence']['plan']
    observed_counts={auth['failed_password_count'],*auth['failed_accounts'].values()}
    if plan: observed_counts.add(plan['maximum_failed_attempts'])
    for count in re.findall(r'\b(\d+)\s+(?:observed\s+)?failed\s+(?:password(?:s)?|login(?:s)?|authentication)(?:\s+attempts?)?',reason,re.I):
        if int(count) not in observed_counts: raise ValueError('Reason invents a failed-password count')
    if auth['successful_login_count'] and re.search(r'\bno successful (?:logins?|authentication)',reason,re.I):
        raise ValueError('Reason denies observed successful authentication')
    if plan and re.search(r'\bno matching approved (?:test )?plan',reason,re.I):
        raise ValueError('Reason denies recorded authorization')
    if re.search(r'\b(known|valid|existing) accounts?\b',reason,re.I):
        raise ValueError('Account existence is not established by failed authentication evidence')
    if auth.get('coverage')=='observed_window' and re.search(r'\b(all activity|nothing else happened|complete proof)\b',reason,re.I):
        raise ValueError('Reason overstates observed-window coverage')
    if re.search(r'(?<!no )(?<!not )\bconfirmed compromise\b',reason,re.I):
        raise ValueError('SSH outcomes do not establish confirmed compromise')
