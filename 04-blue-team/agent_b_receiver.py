"""Agent B: verify every message signature before processing the message."""
import base64
import binascii
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from agent_identity import SIGNED_FIELDS, canonical_bytes, send_from_agent_a

KEY_DIR = Path(__file__).resolve().parent / "keys"

# Only senders listed here have a key that Agent B trusts
TRUSTED_SENDERS = {"agent-a": KEY_DIR / "agent_public.pem"}


class MessageRejected(Exception):
    """Raised when a message fails identity or signature checks."""


def verify_message(message):
    """Raise MessageRejected unless the message has a valid signature."""
    missing = [f for f in (*SIGNED_FIELDS, "signature") if f not in message]
    if missing:
        raise MessageRejected(f"missing field(s): {', '.join(missing)}")

    key_path = TRUSTED_SENDERS.get(message["sender"])
    if key_path is None:
        raise MessageRejected(f"unknown sender: {message['sender']}")

    try:
        signature = base64.b64decode(message["signature"], validate=True)
    except (binascii.Error, ValueError) as error:
        raise MessageRejected("signature is not valid base64") from error

    public_key = load_pem_public_key(key_path.read_bytes())
    try:
        public_key.verify(signature, canonical_bytes(message))
    except InvalidSignature as error:
        raise MessageRejected("signature verification failed") from error


def process_message(message):
    """Agent B's work, reached only after verification succeeds."""
    return f"Agent B processed: {message['content']}"


def receive_at_agent_b(message):
    """Verify first, then process. A rejected message is never processed."""
    verify_message(message)
    return process_message(message)


if __name__ == "__main__":
    signed = send_from_agent_a("agent-b", "Customer asked for the status of order 1042.")
    print("Verification: ACCEPTED")
    print(receive_at_agent_b(signed))