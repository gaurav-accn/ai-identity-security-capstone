"""Run all Project 3 payloads through the NeMo input guardrail."""
import asyncio
import json
import logging
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from nemoguardrails import LLMRails, RailsConfig

from guardrail_rules import find_matches

logging.disable(logging.INFO)

BASE = Path(__file__).resolve().parent
LOG_DIR = BASE / "logs"
RAIL_OPTIONS = {"rails": ["input"], "log": {"activated_rails": True}}

# Store the rules triggered by the last request so the result record can explain why a payload was blocked.
last_matches = []


# NeMo calls this action for each input and returns a block verdict when any suspicious pattern matches.
async def check_identity_attack(text: str):
    """NeMo action: record matched rules and return the verdict."""
    last_matches[:] = find_matches(text)
    return "BLOCK" if last_matches else "PASS"

# Combine the user context with the untrusted payload to mirror the real attack path seen by the model.
def build_text(item):
    """Combine the user's request with the untrusted attack text."""
    parts = [item["user_input"], item["payload"]]
    return "\n\n".join(p for p in dict.fromkeys(parts) if p)

# Run every payload through the rail and keep the per-result verdicts for the final summary.
async def run_all(rails, payloads):
    results = []
    for item in payloads:
        response = await rails.generate_async(
            messages=[{"role": "user", "content": build_text(item)}],
            options=RAIL_OPTIONS,
        )
        blocked = any(r.stop for r in response.log.activated_rails)
        results.append({
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "finding": item["finding"],
            "attack": item["attack"],
            "variant": item["variant"],
            "channel": item["channel"],
            "status": "BLOCKED" if blocked else "PASS",
            "reason": ", ".join(last_matches) if blocked else "no rule matched",
            "payload_verbatim": item["payload"],
        })
    return results

# Initialize the model rails, emit the blocked-by-attack summary, and save the detailed JSON log.
def main():
    payloads = json.loads((BASE / "payloads.json").read_text(encoding="utf-8"))
    config = RailsConfig.from_path(str(BASE / "guardrails_config"))
    rails = LLMRails(config)
    rails.register_action(check_identity_attack, "check_identity_attack")

    results = asyncio.run(run_all(rails, payloads))

    print(f"{'Finding':<8}{'Variant':<26}{'Status':<9}Reason")
    print("-" * 78)
    for r in results:
        print(f"{r['finding']:<8}{r['variant'][:24]:<26}{r['status']:<9}{r['reason']}")

    totals = defaultdict(lambda: [0, 0])
    for r in results:
        totals[r["finding"]][1] += 1
        totals[r["finding"]][0] += r["status"] == "BLOCKED"

    print("\nBlocked by attack")
    for finding, (blocked, total) in totals.items():
        print(f"  {finding}: {blocked}/{total}")
    overall = sum(r["status"] == "BLOCKED" for r in results)
    print(f"\nTotal blocked: {overall}/{len(results)}")

    LOG_DIR.mkdir(exist_ok=True)
    path = LOG_DIR / "guardrail_log.json"
    path.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Saved: logs/{path.name}")


if __name__ == "__main__":
    main()
    