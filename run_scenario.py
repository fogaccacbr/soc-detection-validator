import subprocess
import time
from datetime import datetime, timezone

from check_alert import find_alerts

# --- Config ---
PARROT = "user@192.168.158.30"
SSH_KEY = "/home/orchestrator/.ssh/validator_parrot"

RULE = "Brute-force SMB success"
ATTACK = "nxc smb 192.168.158.20 -u 'Win10 Lab' -p /home/user/wordlists/passwords.txt"
TIMEOUT = 600   # seconds waiting for the alert
INTERVAL = 15   # seconds between each query


def run_attack(command):
    """Execute the attack command on Parrot via SSH."""
    return subprocess.run(
        ["ssh", "-i", SSH_KEY, PARROT, command],
        capture_output=True,
        text=True,
    )


def wait_for_alert(rule, since, timeout, interval):
    """Query the SIEM repeatedly until it finds the alert or hits the time limit."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        hits = find_alerts(rule, since)
        if hits["total"]["value"] > 0:
            return hits["hits"][0]["_source"]["@timestamp"]
        time.sleep(interval)
    return None


if __name__ == "__main__":
    start = datetime.now(timezone.utc)
    print(f"[*] Attack start: {start.isoformat()}")

    result = run_attack(ATTACK)
    print(f"[*] Attack finished (exit code {result.returncode})")
    print(result.stdout)
    if result.stderr:
        print(f"[!] stderr:\n{result.stderr}")

    print(f"[*] Waiting up to {TIMEOUT}s for '{RULE}'...")
    detected_at = wait_for_alert(RULE, start.isoformat(), TIMEOUT, INTERVAL)

    if detected_at:
        delay = datetime.fromisoformat(detected_at) - start
        print(f"[+] DETECTED in {delay.total_seconds():.0f}s")
    else:
        print(f"[-] NOT DETECTED within {TIMEOUT}s")
