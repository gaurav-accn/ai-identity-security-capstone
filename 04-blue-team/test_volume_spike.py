"""Check the volume spike rule below, at and above its limit."""
from datetime import datetime, timedelta, timezone

from anomaly_detector import process_events

start = datetime(2026, 11, 10, 10, 0, tzinfo=timezone.utc)

# Generate a time-ordered burst so the volume rule can be tested at, below, and above the allowed threshold.
def events(count, gap_seconds):
    return [{
        "timestamp": (start + timedelta(seconds=i * gap_seconds)).isoformat(),
        "identity": "securenova-chat-agent-01",
        "event_type": "llm_request",
        "scopes": ["read:ai-data"],
        "token_expires_at": (start + timedelta(minutes=5)).isoformat(),
    } for i in range(count)]


# Verify that a burst below the limit remains within the allowed request window and is not flagged.
print("Test 1: 20 requests in 19 seconds")
print("Alerts:", len(process_events(events(20, 1))))
# Check the first threshold crossing, where the rolling 60-second window exceeds the permitted request count.
print("\nTest 2: 21 requests in 20 seconds")
print("Alerts:", len(process_events(events(21, 1))))
# Confirm that the same request count spread over a longer interval stays inside the allowed rate and does not trip the alert.
print("\nTest 3: 21 requests spread over 100 seconds")
print("Alerts:", len(process_events(events(21, 5))))
# Stress the rule with a larger burst to confirm it continues to flag sustained high-volume abuse.
print("\nTest 4: 30 requests in 29 seconds")
print("Alerts:", len(process_events(events(30, 1))))