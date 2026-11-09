"""Check the token reuse rule before, at and after expiry."""
from anomaly_detector import process_events

EXPIRES = "2026-11-10T10:05:00+00:00"


def event(timestamp):
    return {
        "timestamp": timestamp,
        "identity": "securenova-chat-agent-01",
        "event_type": "token_replay",
        "scopes": ["read:ai-data"],
        "token_expires_at": EXPIRES,
    }


print("Test 1: one second before expiry")
print("Alerts:", len(process_events([event("2026-11-10T10:04:59+00:00")])))

print("\nTest 2: exactly at expiry")
print("Alerts:", len(process_events([event("2026-11-10T10:05:00+00:00")])))

print("\nTest 3: 65 seconds after expiry")
print("Alerts:", len(process_events([event("2026-11-10T10:06:05+00:00")])))