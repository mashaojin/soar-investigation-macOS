"""Local macOS lab identity shared with the staged guest client."""
import ipaddress
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent
UTM = '/Applications/UTM.app/Contents/MacOS/utmctl'
FILENAME = 'topology.local.json'
DEFAULT = {
    'victim': {'name': 'Victim', 'user': 'victim', 'ip': '192.168.64.6'},
    'kali': {'name': 'Kali Linux', 'user': 'kali', 'ip': '192.168.64.4'},
    'trusted': {'name': 'Trust-Client', 'user': 'trust-client', 'ip': '192.168.64.8'},
    'management_ip': '192.168.64.1',
}


def load(root=ROOT):
    try:
        value = json.loads((root / FILENAME).read_text())
    except FileNotFoundError:
        value = DEFAULT
    return validate(value)


def validate(value):
    try:
        guests = [value[role] for role in ('victim', 'kali', 'trusted')]
        ips = [str(ipaddress.IPv4Address(guest['ip'])) for guest in guests]
        ips.append(str(ipaddress.IPv4Address(value['management_ip'])))
        names = [guest['name'] for guest in guests]
        if (len(set(ips)) != 4 or len(set(names)) != 3
                or any(not name.strip() or name.startswith('-') or any(ord(c) < 32 for c in name)
                       for name in names)
                or any(not re.fullmatch(r'[a-z_][a-z0-9_-]*', guest['user']) for guest in guests)
                or any(guest['ip'] != ip for guest, ip in zip(guests, ips))
                or value['management_ip'] != ips[-1]):
            raise ValueError
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise ValueError('Topology requires distinct IPv4 addresses, three distinct UTM names and valid guest usernames') from exc
    return value


def clients(topology):
    return {topology[role]['ip']: topology[role] for role in ('kali', 'trusted')}


def ssh_target(topology):
    return '{user}@{ip}'.format(**topology['victim'])


def collector_config(config, root=ROOT):
    if not (root / FILENAME).exists():
        return config
    topology = load(root)
    return dict(config, ssh_target=ssh_target(topology), source_ips=list(clients(topology)),
                destination_ip=topology['victim']['ip'])


def response_config(policy, root=ROOT):
    if not (root / FILENAME).exists():
        return policy
    topology = load(root)
    victim = topology['victim']['ip']
    return dict(policy, victim_ip=victim, allowed_attacker_ips=list(clients(topology)),
                protected_ips=sorted(set(policy['protected_ips']) | {victim, topology['management_ip']}),
                _topology=topology)


def verify_management(connection, topology):
    fields = (connection or '').split()
    if (len(fields) != 4 or fields[0] != topology['management_ip']
            or fields[2:] != [topology['victim']['ip'], '22']):
        raise ValueError('Victim SSH_CONNECTION does not confirm the configured management source and victim TCP/22')
