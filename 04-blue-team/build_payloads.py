"""Collect the exact Project 3 attack inputs into payloads.json."""
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
LOGS = BASE.parent / "03-red-team" / "logs"
OUTPUT = BASE / "payloads.json"

# Read the relevant red-team logs from their known location so we can build a single canonical payload set.
def load(name):
    with open(LOGS / name, encoding="utf-8") as f:
        return json.load(f)

# Normalize each finding into a single metadata record so every payload can be compared consistently.
def entry(finding, attack, owasp, variant, channel, payload, source, user_input=""):
    return {
        "finding": finding,
        "attack": attack,
        "owasp": owasp,
        "variant": variant,
        "channel": channel,      # where the attack text enters the agent
        "user_input": user_input,
        "payload": payload,      # verbatim text the guardrail must scan
        "source_log": source,
    }

# Convert document chunks to plain text regardless of whether the source log stored them as a string or a dictionary.
def doc_to_text(doc):
    """Retrieved documents may be logged as strings or as dictionaries."""
    if isinstance(doc, str):
        return doc
    if isinstance(doc, dict):
        for key in ("text", "content", "chunk", "document"):
            if key in doc:
                return str(doc[key])
    return json.dumps(doc, ensure_ascii=False)

# Deduplicate by a chosen field while preserving the first occurrence so repeated records do not inflate the dataset.
def first_per(rows, key):
    """Keep one row for each distinct value of key, in log order."""
    seen = {}
    for row in rows:
        seen.setdefault(row[key], row)
    return list(seen.values())


payloads = []

# F-1: three documents, each hiding a different injection; each row becomes one canonical payload entry.
for row in first_per(load("attack1_log.json"), "payload_file"):
    payloads.append(entry(
        "F-1", "Indirect Prompt Injection", "LLM01", row["payload_file"], "document",
        row["payload_verbatim"], "attack1_log.json", row["user_question"],
    ))

# F-2: spoofed agent message only; the normal-user control is not an attack, so we filter only the malicious cases.
spoofed = [r for r in load("attack2_log.json") if "spoof" in str(r["test"]).lower()]
for row in first_per(spoofed, "message_verbatim"):
    payloads.append(entry(
        "F-2", "Agent Identity Spoofing", "LLM09", row["test"], "agent_message",
        row["message_verbatim"], "attack2_log.json",
    ))

# F-3: one prompt for each extraction technique, preserving the distinct strategy names for the final dataset.
for row in first_per(load("attack3_log.json"), "technique"):
    payloads.append(entry(
        "F-3", "System Prompt Extraction", "LLM07", row["technique"], "user_prompt",
        row["prompt_verbatim"], "attack3_log.json", row["prompt_verbatim"],
    ))

# F-4 and F-5: the same poisoned retrieval drives both findings, so we merge the retrieved context into both entries.
poisoned = [r for r in load("attack4_log.json") if "poison" in str(r["condition"]).lower()]
if poisoned:
    row = poisoned[0]
    text = "\n\n".join(doc_to_text(d) for d in row["retrieved_documents"])
    payloads.append(entry(
        "F-4", "RAG Poisoning", "LLM08", "poisoned_retrieval", "retrieved_context",
        text, "attack4_log.json", row["question"],
    ))
    payloads.append(entry(
        "F-5", "MCP Abuse", "LLM06", "poisoned_tool_request", "retrieved_context",
        text, "attack4_log.json", row["question"],
    ))

expected = {"F-1": 3, "F-2": 1, "F-3": 5, "F-4": 1, "F-5": 1}
counts = {f: sum(p["finding"] == f for p in payloads) for f in expected}

# Save the final canonical payload list and verify each finding count matches the expected source data.
with open(OUTPUT, "w", encoding="utf-8") as f:
    json.dump(payloads, f, indent=2, ensure_ascii=False)

# Print a compact summary showing whether each attack type was captured at the expected cardinality.
print(f"{'Finding':<8}{'Attack':<28}{'Found':>6}{'Expected':>10}  Status")
for finding, want in expected.items():
    name = next((p["attack"] for p in payloads if p["finding"] == finding), "MISSING")
    status = "OK" if counts[finding] == want else "CHECK"
    print(f"{finding:<8}{name:<28}{counts[finding]:>6}{want:>10}  {status}")

empty = sum(not p["payload"].strip() for p in payloads)
print(f"\nTotal payloads: {len(payloads)} | Empty payloads: {empty}")
print(f"Saved: {OUTPUT.name}")