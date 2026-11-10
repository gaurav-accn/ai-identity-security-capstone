"""Check the token reuse rule before, at and after expiry."""
from anomaly_detector import process_events

EXPIRES = "2026-11-10T10:05:00+00:00"

# Build a single token-replay event so each test isolates the expiry boundary condition.
def event(timestamp):
    return {
        "timestamp": timestamp,
        "identity": "securenova-chat-agent-01",
        "event_type": "token_replay",
        "scopes": ["read:ai-data"],
        "token_expires_at": EXPIRES,
    }


# Confirm that a request just before expiry is still valid and does not count as token reuse.
print("Test 1: one second before expiry")
print("Alerts:", len(process_events([event("2026-11-10T10:04:59+00:00")])))

# Verify that the boundary condition does not trigger on the exact expiry timestamp.
print("\nTest 2: exactly at expiry")
print("Alerts:", len(process_events([event("2026-11-10T10:05:00+00:00")])))

# Check that stale token use after expiry is recognized and escalated as a reuse violation.
print("\nTest 3: 65 seconds after expiry")
print("Alerts:", len(process_events([event("2026-11-10T10:06:05+00:00")])))