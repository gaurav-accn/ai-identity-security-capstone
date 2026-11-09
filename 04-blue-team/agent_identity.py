"""Sign messages sent by Agent A with its Ed25519 private key."""
import base64
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_private_key

KEY_DIR = Path(__file__).resolve().parent / "keys"
SIGNED_FIELDS = ("sender", "recipient", "timestamp", "content")


def canonical_bytes(message):
    """Build the exact bytes that are signed and later verified."""
    data = {field: message[field] for field in SIGNED_FIELDS}
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_message(message):
    """Return a copy of the message with its base64 Ed25519 signature."""
    key_bytes = (KEY_DIR / "agent_private.pem").read_bytes()
    private_key = load_pem_private_key(key_bytes, password=None)
    signature = private_key.sign(canonical_bytes(message))
    return {**message, "signature": base64.b64encode(signature).decode("ascii")}


def send_from_agent_a(recipient, content):
    """The only send path for Agent A, so every outgoing message is signed."""
    message = {
        "sender": "agent-a",
        "recipient": recipient,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "content": content,
    }
    return sign_message(message)


if __name__ == "__main__":
    signed = send_from_agent_a("agent-b", "Customer asked for the status of order 1042.")
    print("Signed outgoing message from Agent A:")
    print(json.dumps(signed, indent=2, ensure_ascii=False))
    print(f"\nSignature size: {len(base64.b64decode(signed['signature']))} bytes")