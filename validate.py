import sys
import time
import subprocess
from datetime import datetime, timezone

import yaml

from check_alert import find_alerts

# --- Config ---
PARROT = "user@192.168.158.30"
SSH_KEY = "/home/orchestrator/.ssh/validator_parrot"
INTERVAL = 15   # seconds between each query to the SIEM


def run_remote(command):
    """Run a command on Parrot via SSH and return the finished process."""
    return subprocess.run(
        ["ssh", "-i", SSH_KEY, PARROT, command],
        capture_output=True,
        text=True,
    )


def wait_for_alert(rule, since, timeout):
    """Poll the SIEM until the rule fires or the timeout is reached."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        hits = find_alerts(rule, since)
        if hits["total"]["value"] > 0:
            return hits["hits"][0]["_source"]["@timestamp"]
        time.sleep(INTERVAL)
    return None


def run_scenario(scenario):
    """Run one scenario and return a result dict."""
    name = scenario["name"]
    print(f"\n=== {scenario['id']} | {name} ===")

    start = datetime.now(timezone.utc)
    result = run_remote(scenario["attack"])

    # Did the attack actually work?
    output = result.stdout + result.stderr
    if scenario["success_signal"] not in output:
        print(f"[!] ATTACK FAILED (signal '{scenario['success_signal']}' not found)")
        return {"scenario": scenario, "status": "ATTACK FAILED", "delay": None}

    print("[*] Attack OK, waiting for the alert...")
    detected_at = wait_for_alert(scenario["rule"], start.isoformat(), scenario["timeout"])

    if detected_at is None:
        print("[-] NOT DETECTED")
        return {"scenario": scenario, "status": "NOT DETECTED", "delay": None}

    delay = (datetime.fromisoformat(detected_at) - start).total_seconds()
    print(f"[+] DETECTED in {delay:.0f}s")

    # Optional cleanup
    if scenario.get("cleanup"):
        print("[*] Running cleanup...")
        run_remote(scenario["cleanup"])

    return {"scenario": scenario, "status": "DETECTED", "delay": delay}


def main():
    with open("scenarios.yaml") as f:
        scenarios = yaml.safe_load(f)

    results = []
    for scenario in scenarios:
        results.append(run_scenario(scenario))

    print("\n\n===== SUMMARY =====")
    for r in results:
        delay = f"{r['delay']:.0f}s" if r["delay"] is not None else "-"
        print(f"{r['scenario']['id']:<12} {r['status']:<14} {delay}")


if __name__ == "__main__":
    main()
