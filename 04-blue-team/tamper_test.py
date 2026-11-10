"""Show that Agent B accepts valid messages and rejects altered or forged ones."""
import base64
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_b_receiver import MessageRejected, receive_at_agent_b
from agent_identity import canonical_bytes, send_from_agent_a

BASE = Path(__file__).resolve().parent
LOG_FILE = BASE / "logs" / "signature_log.json"

# Flip one character in a valid message so the test can prove the signature check catches even a tiny alteration.
def change_one_character(text, position):
    """Replace exactly one character and describe the change."""
    old = text[position]
    new = "X" if old != "X" else "Y"
    changed = text[:position] + new + text[position + 1:]
    return changed, f"position {position}: '{old}' -> '{new}'"

# Forge a message with an attacker key while claiming to come from Agent A to verify the receiver rejects spoofed senders.
def forged_message(content):
    """Claim to be Agent A, but sign with an attacker's own key."""
    message = {
        "sender": "agent-a",
        "recipient": "agent-b",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "content": content,
    }
    attacker_key = Ed25519PrivateKey.generate()
    signature = attacker_key.sign(canonical_bytes(message))
    return {**message, "signature": base64.b64encode(signature).decode("ascii")}

# Deliver a single scenario to Agent B and record whether the signature check accepts or rejects it.
def run_case(name, message, change):
    """Send one message to Agent B and record the outcome."""
    entry = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "case": name,
        "claimed_sender": message["sender"],
        "change": change,
    }
    try:
        receive_at_agent_b(message)
        entry.update(status="ACCEPTED", reason="signature valid")
        print(f"[INFO]  {name}: ACCEPTED | sender={message['sender']} | signature valid")
    except MessageRejected as error:
        entry.update(status="REJECTED", reason=str(error))
        print(f"[ERROR] {name}: REJECTED | sender={message['sender']} | {error}")
        if change != "none":
            print(f"        Change: {change}")
    return entry

# Exercise valid, tampered, and forged messages so the results show the signal strength of the signature gate.
def main():
    payloads = json.loads((BASE / "payloads.json").read_text(encoding="utf-8"))
    spoofed = next(p for p in payloads if p["finding"] == "F-2")

    valid = send_from_agent_a("agent-b", "Customer asked for the status of order 1042.")
    new_content, change = change_one_character(valid["content"], 9)
    tampered = {**valid, "content": new_content}

    results = [
        run_case("VALID_MESSAGE", valid, "none"),
        run_case("TAMPERED_ONE_CHARACTER", tampered, change),
        run_case(spoofed["variant"], forged_message(spoofed["payload"]),
                 "signed with an attacker key, not Agent A's key"),
    ]

    LOG_FILE.parent.mkdir(exist_ok=True)
    LOG_FILE.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nSaved: logs/{LOG_FILE.name}")


if __name__ == "__main__":
    main()