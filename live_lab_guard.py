"""Root guest helper for ONE allowlisted 60-second client-to-Ubuntu SSH lab test."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time


ROLLBACK = r'''
import json, pathlib, re, subprocess, sys, time
folder = pathlib.Path(__file__).resolve().parent
tag = 'soc-lab-' + folder.name
def command(args):
    return subprocess.run(args, text=True, capture_output=True, timeout=15, check=True).stdout
def save(state):
    temporary = folder / 'state.tmp'
    temporary.write_text(json.dumps(state))
    temporary.chmod(0o644)
    temporary.replace(folder / 'state.json')
state = json.loads((folder / 'state.json').read_text())
for attempt in range(3):
    try:
        before = command(['/usr/sbin/ufw', 'status', 'numbered'])
        matches = [line for line in before.splitlines() if line.endswith('# ' + tag)]
        if len(matches) > 1:
            raise RuntimeError('Ambiguous tagged rule; manual recovery required')
        if matches:
            line = matches[0]
            if state['source'] not in ('192.168.64.4','192.168.64.8') or state['source'] not in line or '192.168.64.6' not in line or '22/tcp' not in line:
                raise RuntimeError('Tagged rule does not match the lab scope')
            number = re.match(r'^\[\s*(\d+)\]', line).group(1)
            command(['/usr/sbin/ufw', '--force', 'delete', number])
        after = command(['/usr/sbin/ufw', 'status', 'numbered'])
        if tag in after:
            raise RuntimeError('Tagged rule is still present')
        state.update(stage='rolled_back', firewall_after=after, rollback_attempts=attempt+1, rolled_back_at=time.time())
        save(state)
        sys.exit(0)
    except Exception as exc:
        state.update(stage='rollback_failed', error=type(exc).__name__ + ': ' + str(exc))
        save(state)
        time.sleep(2)
sys.exit(1)
'''


def main():
    run_id = sys.argv[1]
    source = sys.argv[2] if len(sys.argv)>2 else '192.168.64.4'
    if source not in ('192.168.64.4','192.168.64.8'):
        raise ValueError('Unsupported lab source')
    if not re.fullmatch(r"[0-9a-f]{24}", run_id) or os.geteuid() != 0:
        raise RuntimeError("Root execution and a valid lab test ID are required")
    folder = Path("/run/soc-lab-tests")
    folder.mkdir(mode=0o755, exist_ok=True)
    if folder.is_symlink() or folder.stat().st_uid != 0 or folder.stat().st_mode & 0o022:
        raise RuntimeError("Unsafe lab state directory")
    folder = folder / run_id
    folder.mkdir(mode=0o755)  # Exclusive create: re-dispatch cannot apply twice.
    tag = "soc-lab-" + run_id
    unit = tag + "-rollback"
    state = dict(stage="preflight", run_id=run_id, tag=tag, timer_unit=unit + ".timer",
                 source=source, destination="192.168.64.6", port=22, duration_seconds=60)
    def save():
        temporary = folder / "state.tmp"
        temporary.write_text(json.dumps(state))
        temporary.chmod(0o644)
        temporary.replace(folder / "state.json")
    def command(args):
        return subprocess.run(args, capture_output=True, text=True, timeout=15, check=True).stdout
    save()
    try:
        interfaces = json.loads(command([shutil.which("ip") or "/usr/sbin/ip", "-j", "address", "show"]))
        if not any(a.get("local") == "192.168.64.6" for interface in interfaces for a in interface.get("addr_info", [])):
            raise RuntimeError("This helper must run on the Ubuntu victim 192.168.64.6")
        before = command(["/usr/sbin/ufw", "status", "numbered"])
        if not before.startswith("Status: active"):
            raise RuntimeError("UFW must already be active")
        if source in before:
            raise RuntimeError("Existing source-specific rule requires review before this test")
        state["firewall_before"] = before
        rollback = folder / "rollback.py"
        rollback.write_text(ROLLBACK)
        rollback.chmod(0o700)
        # Timer is armed and verified BEFORE the deny is applied. It runs on Ubuntu.
        armed_at = time.monotonic()
        armed_epoch = time.time()
        command(["/usr/bin/systemd-run", "--quiet", "--unit=" + unit,
                 "--on-active=60s", "--timer-property=AccuracySec=1s",
                 "--property=Restart=on-failure", "--property=RestartSec=5s",
                 "/usr/bin/python3", str(rollback)])
        if command(["/usr/bin/systemctl", "is-active", unit + ".timer"]).strip() != "active":
            raise RuntimeError("Rollback timer is not active")
        if time.monotonic() - armed_at >= 10:
            raise RuntimeError("Timer setup was too slow; no block will be added")
        state.update(stage="armed", timer_armed_at=armed_epoch, rollback_due_at=armed_epoch+60)
        save()
        command(["/usr/sbin/ufw", "insert", "1", "deny", "from", source,
                 "to", "192.168.64.6", "port", "22", "proto", "tcp", "comment", tag])
        after = command(["/usr/sbin/ufw", "status", "numbered"])
        if tag not in after:
            raise RuntimeError("Tagged deny rule was not found")
        state.update(stage="applied", firewall_applied=after, applied_at=time.time())
        save()
    except Exception as exc:
        state.update(stage="apply_failed", error=type(exc).__name__ + ": " + str(exc))
        save()
        if (folder / "rollback.py").exists():
            subprocess.run(["/usr/bin/python3", str(folder / "rollback.py")], timeout=60)
        raise


if __name__ == "__main__":
    main()
