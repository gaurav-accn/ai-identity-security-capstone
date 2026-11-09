"""Detection rules used by the NeMo input rail."""
import re

FLAGS = re.IGNORECASE | re.DOTALL

SECRET = r"(credential|jwt|bearer token|session token|access token|api key|secret)"
DISCLOSE = r"(include|reveal|print|output|send|share|append|repeat|show|disclose|copy|provide)"

RULES = [
    ("credential_exfiltration",
     rf"\b{DISCLOSE}\b.{{0,120}}\b{SECRET}\b"),
    ("instruction_override",
     r"\b(ignore|disregard|forget|override|bypass)\b.{0,60}\b(instructions?|rules?|prompts?|guidelines?|restrictions?)\b"),
    ("system_prompt_extraction",
     rf"(\b{DISCLOSE}\b|\btranslate\b|\bsummari[sz]e\b|\bencode\b).{{0,80}}\b(system (prompt|message)|(hidden|initial|original|your) instructions?)\b"),
    ("fake_authority_note",
     r"\b(system|admin|administrator|developer)\s+(note|notice|message|override)\b|\b(any|all|automated)\s+(ai\s+)?(assistants?|agents?)\b.{0,60}\b(must|should|shall|required)\b"),
    ("hidden_instruction",
     r"<!--.*?\b(assistant|agent|instructions?|credential|token|model)\b.*?-->"),
    ("unauthorised_tool_request",
     r"\bsend_report\b"),
]

COMPILED = [(name, re.compile(pattern, FLAGS)) for name, pattern in RULES]


def find_matches(text):
    """Return the names of every rule that matches the text."""
    return [name for name, pattern in COMPILED if pattern.search(text)]