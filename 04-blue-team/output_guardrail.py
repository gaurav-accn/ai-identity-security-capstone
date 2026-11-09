"""Output guardrail: detect and redact JWT-shaped strings in model replies."""
import json
import re
from pathlib import Path

BASE = Path(__file__).resolve().parent
LEAK_LOG = BASE.parent / "03-red-team" / "logs" / "attack1_log.json"
OUTPUT_LOG = BASE / "logs" / "output_guardrail_log.json"

# A JWT has three base64url parts separated by dots, and its header starts with eyJ
JWT_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"
)
REDACTION = "[REDACTED]"


def redact_jwt(text):
    """Return the redacted text and the number of JWT-shaped strings replaced."""
    return JWT_PATTERN.subn(REDACTION, text)


def snippet(text, marker, width=70):
    """Show the part of a long reply around the first marker."""
    start = text.find(marker)
    if start < 0:
        return text[:160]
    return text[max(0, start - width):start + len(marker) + width].replace("\n", " ")


def main():
    rows = json.loads(LEAK_LOG.read_text(encoding="utf-8"))
    leaked = [r for r in rows if r["result"] == "LEAKED"]

    results = []
    for row in leaked:
        original = row["full_model_response"]
        redacted, count = redact_jwt(original)
        results.append({
            "payload_file": row["payload_file"],
            "run": row["run"],
            "jwt_strings_redacted": count,
            "jwt_remaining_after": bool(JWT_PATTERN.search(redacted)),
            "original_response": original,
            "redacted_response": redacted,
        })

    fired = [r for r in results if r["jwt_strings_redacted"] > 0]
    if fired:
        example = fired[0]
        token = JWT_PATTERN.search(example["original_response"]).group(0)
        print("OUTPUT GUARDRAIL: JWT DETECTED AND REDACTED")
        print(f"Source: {example['payload_file']}, run {example['run']}\n")
        print("BEFORE (model response):")
        print(f"  ...{snippet(example['original_response'], token)}...\n")
        print("AFTER (returned to user):")
        print(f"  ...{snippet(example['redacted_response'], REDACTION)}...\n")

    remaining = sum(r["jwt_remaining_after"] for r in results)
    print(f"Leaked responses tested : {len(results)}")
    print(f"Responses redacted      : {len(fired)}/{len(results)}")
    print(f"JWTs left after redaction: {remaining}")

    clean = "Your order will arrive on Friday. Version 1.2.3 is installed."
    print(f"Clean text unchanged    : {redact_jwt(clean)[0] == clean}")

    OUTPUT_LOG.parent.mkdir(exist_ok=True)
    OUTPUT_LOG.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Saved: logs/{OUTPUT_LOG.name}")


if __name__ == "__main__":
    main()