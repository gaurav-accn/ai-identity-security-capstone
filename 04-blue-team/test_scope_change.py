"""Check that the scope rule compares consecutive requests per identity."""
from anomaly_detector import process_events

EXPIRES = "2026-11-10T10:05:00+00:00"

# Build one synthetic event so each scope test exercises the same request shape with different permissions.
def event(second, identity, scopes):
    return {
        "timestamp": f"2026-11-10T10:00:{second:02d}+00:00",
        "identity": identity,
        "event_type": "agent_request",
        "scopes": scopes,
        "token_expires_at": EXPIRES,
    }


AGENT = "securenova-chat-agent-01"
OTHER = "securenova-help-agent-02"

# Confirm that repeated requests from the same agent do not trigger a scope-change alert without a permission delta.
print("Test 1: same scope on both requests")
print("Alerts:", len(process_events([
    event(0, AGENT, ["read:ai-data"]),
    event(5, AGENT, ["read:ai-data"]),
])))

# Verify that a user gains new privileges in a later request and triggers the scope-drift rule.
print("\nTest 2: agent gains write:admin")
print("Alerts:", len(process_events([
    event(0, AGENT, ["read:ai-data"]),
    event(5, AGENT, ["read:ai-data", "write:admin"]),
])))

# Check that the rule only compares scope changes for the same identity, not across unrelated agents.
print("\nTest 3: two different agents with different scopes")
print("Alerts:", len(process_events([
    event(0, AGENT, ["read:ai-data"]),
    event(5, OTHER, ["write:admin"]),
])))