"""Platform-selected SSH argv; all commands originate in bounded Python operations."""
from pathlib import Path
import re
import shlex
import subprocess
from lab_config import validate_profile


def windows_path(path):
    path=str(path)
    match=re.fullmatch(r'/mnt/([a-zA-Z])/(.*)',path)
    if match:return match[1].upper()+':\\'+match[2].replace('/','\\')
    return subprocess.check_output(['wslpath','-w',path],text=True,timeout=5).strip()


def command(profile,role,remote_command):
    profile=validate_profile(profile)
    if role not in ('victim','trust_client','attacker'):raise ValueError('Unsupported SSH role')
    host=profile[role];ssh=profile['ssh']
    argv=['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
          '-o','ConnectTimeout=5','-o','ConnectionAttempts=1',
          '-o','ServerAliveInterval=5','-o','ServerAliveCountMax=2',
          '-o','ForwardAgent=no','-o','ClearAllForwardings=yes']
    if ssh.get('identity_file'):
        argv+=['-o','IdentitiesOnly=yes','-i',str(Path(ssh['identity_file']).expanduser())]
    if ssh.get('known_hosts_file'):
        argv+=['-o','UserKnownHostsFile='+str(Path(ssh['known_hosts_file']).expanduser()),'-o','GlobalKnownHostsFile=/dev/null']
    if ssh['transport']=='windows-stdio':
        if not profile.get('_path'):raise ValueError('Windows transport requires an explicit on-disk lab profile')
        proxy=[ssh['windows_powershell'],'-NoLogo','-NoProfile','-NonInteractive','-File',
               windows_path(Path(__file__).with_name('windows_tcp_proxy.ps1')),
               '-ProfilePath',windows_path(profile['_path']),'-Target',host['ip'],'-Port','22']
        argv+=['-o','ProxyCommand='+shlex.join(proxy)]
    return argv+[host['user']+'@'+host['ip'],remote_command]
