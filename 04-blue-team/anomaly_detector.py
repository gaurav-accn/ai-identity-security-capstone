"""Detect suspicious AI agent activity from a stream of security events."""
from collections import defaultdict, deque
from datetime import datetime

REQUIRED_FIELDS = ("timestamp", "identity", "event_type", "scopes", "token_expires_at")


def parse_time(value):
    """Convert an ISO 8601 timestamp into a datetime."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def validate_event(event):
    """Reject incomplete events so that a rule never reads missing data."""
    missing = [field for field in REQUIRED_FIELDS if field not in event]
    if missing:
        raise ValueError(f"Event is missing field(s): {', '.join(missing)}")


class DetectorState:
    """Remember earlier events for each identity."""

    def __init__(self):
        self.request_times = defaultdict(deque)
        self.last_scopes = {}


def make_alert(event, alert_type, detail):
    """Create an alert with the fields required by the brief."""
    return {
        "timestamp": event["timestamp"],
        "identity": event["identity"],
        "event_type": alert_type,
        "detail": detail,
    }


VOLUME_WINDOW_SECONDS = 60
VOLUME_LIMIT = 20


def detect_volume_spike(event, state):
    """Alert when an identity makes more than 20 LLM requests in 60 seconds."""
    if event["event_type"] != "llm_request":
        return None

    now = parse_time(event["timestamp"])
    times = state.request_times[event["identity"]]
    times.append(now)

    # Keep only the requests still inside the sliding window
    while (now - times[0]).total_seconds() >= VOLUME_WINDOW_SECONDS:
        times.popleft()

    # Alert once when the limit is crossed, not on every later request
    if len(times) == VOLUME_LIMIT + 1:
        return make_alert(
            event, "LLM_VOLUME_SPIKE",
            f"{len(times)} requests in {VOLUME_WINDOW_SECONDS} seconds (limit {VOLUME_LIMIT})",
        )
    return None


AGENT_REQUEST_TYPES = ("llm_request", "agent_request")


def detect_scope_change(event, state):
    """Alert when an identity's scopes differ from its previous request."""
    if event["event_type"] not in AGENT_REQUEST_TYPES:
        return None

    identity = event["identity"]
    current = set(event["scopes"])
    previous = state.last_scopes.get(identity)
    state.last_scopes[identity] = current

    if previous is None or current == previous:
        return None

    added = sorted(current - previous) or ["none"]
    removed = sorted(previous - current) or ["none"]
    return make_alert(
        event, "SCOPE_CHANGE",
        f"added={', '.join(added)} removed={', '.join(removed)}",
    )


def detect_token_reuse(event, state):
    """Alert when a token is used at or after its expiry time."""
    now = parse_time(event["timestamp"])
    expires = parse_time(event["token_expires_at"])
    if now < expires:
        return None

    seconds_late = int((now - expires).total_seconds())
    return make_alert(
        event, "TOKEN_REUSE_AFTER_EXPIRY",
        f"token used {seconds_late} seconds after expiry at {event['token_expires_at']}",
    )


RULES = [detect_volume_spike, detect_scope_change, detect_token_reuse]


def process_events(events):
    """Run every rule on each event in time order and return all alerts."""
    state = DetectorState()
    alerts = []
    for event in events:
        validate_event(event)
    for event in sorted(events, key=lambda e: parse_time(e["timestamp"])):
        for rule in RULES:
            alert = rule(event, state)
            if alert:
                alerts.append(alert)
                print(f"[ALERT] {alert['timestamp']} | identity={alert['identity']} | "
                      f"event_type={alert['event_type']} | {alert['detail']}")
    return alerts


if __name__ == "__main__":
    sample_events = [
        {
            "timestamp": "2026-11-10T10:00:00+00:00",
            "identity": "securenova-chat-agent-01",
            "event_type": "llm_request",
            "scopes": ["read:ai-data"],
            "token_expires_at": "2026-11-10T10:05:00+00:00",
        },
        {
            "timestamp": "2026-11-10T10:00:10+00:00",
            "identity": "securenova-chat-agent-01",
            "event_type": "llm_request",
            "scopes": ["read:ai-data"],
            "token_expires_at": "2026-11-10T10:05:00+00:00",
        },
    ]
    found = process_events(sample_events)
    print(f"Events processed: {len(sample_events)}")
    print(f"Rules loaded    : {len(RULES)}")
    print(f"Alerts raised   : {len(found)}")