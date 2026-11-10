"""Replay Project 3 attacks as security events and confirm each alert fires."""
import json
from datetime import datetime, timedelta, timezone
from itertools import cycle, islice
from pathlib import Path

from anomaly_detector import process_events

BASE = Path(__file__).resolve().parent
LOG_FILE = BASE / "logs" / "anomaly_alerts.json"
AGENT = "securenova-chat-agent-01"
READ_ONLY = ["read:ai-data"]
ESCALATED = ["read:ai-data", "write:admin"]

# Build one normalized event record per scenario so the detector receives the same event shape across all replay cases.
def build_event(moment, event_type, scopes, expires, attack):
    return {
        "timestamp": moment.isoformat(timespec="seconds"),
        "identity": AGENT,
        "event_type": event_type,
        "scopes": scopes,
        "token_expires_at": expires.isoformat(timespec="seconds"),
        "replayed_attack": attack,
    }

# Replay the payload set at a rate that exceeds the allowed volume threshold to verify the spike detector fires.
def volume_scenario(payloads, start):
    """Send Project 3 payloads faster than the allowed request rate."""
    expires = start + timedelta(minutes=5)
    replayed = islice(cycle(payloads), 25)
    return [
        build_event(start + timedelta(seconds=i), "llm_request", READ_ONLY, expires, p["finding"])
        for i, p in enumerate(replayed)
    ]

# Simulate a legitimate request followed by a privilege escalation so the scope-change rule can compare before and after.
def scope_scenario(start):
    """A normal request followed by the F-2 spoofed request asking for admin."""
    expires = start + timedelta(minutes=5)
    return [
        build_event(start, "agent_request", READ_ONLY, expires, "normal request"),
        build_event(start + timedelta(seconds=5), "agent_request", ESCALATED, expires, "F-2"),
    ]

# Reuse a token after expiry to confirm the detector catches stale credentials that continue acting beyond their valid window.
def token_scenario(start):
    """Replay an attack request 65 seconds after its token expired."""
    expires = start - timedelta(seconds=65)
    return [build_event(start, "token_replay", READ_ONLY, expires, "F-1")]

# Run each attack scenario in sequence and compare the actual alerts against the expected rule-specific findings.
def main():
    payloads = json.loads((BASE / "payloads.json").read_text(encoding="utf-8"))
    start = datetime.now(timezone.utc).replace(microsecond=0)

    scenarios = [
        ("Volume spike", "LLM_VOLUME_SPIKE", volume_scenario(payloads, start)),
        ("Scope change", "SCOPE_CHANGE", scope_scenario(start)),
        ("Token reuse", "TOKEN_REUSE_AFTER_EXPIRY", token_scenario(start)),
    ]

    all_alerts = []
    summary = []
    for name, expected, events in scenarios:
        print(f"--- Scenario: {name} ({len(events)} events) ---")
        alerts = process_events(events)
        fired = any(a["event_type"] == expected for a in alerts)
        complete = all(a["timestamp"] and a["identity"] and a["event_type"] for a in alerts)
        status = "CONFIRMED" if fired and complete else "NOT FIRED"
        summary.append((name, expected, status))
        all_alerts.extend(alerts)
        print()

    print(f"{'Scenario':<16}{'Expected alert':<28}Result")
    print("-" * 56)
    for name, expected, status in summary:
        print(f"{name:<16}{expected:<28}{status}")

    LOG_FILE.parent.mkdir(exist_ok=True)
    LOG_FILE.write_text(json.dumps(all_alerts, indent=2), encoding="utf-8")
    print(f"\nSaved: logs/{LOG_FILE.name}")


if __name__ == "__main__":
    main()