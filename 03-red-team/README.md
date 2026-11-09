# Project 3 – Red Team: AI Identity Attacks

## Goal
Attack a simulated SecureNova AI agent before any defences are added,
score each successful attack with CVSS 3.1, map it to MITRE ATLAS, and
set the baseline for the Project 4 before/after comparison.

## Setup
All tests use simulated agents with `gemini-flash-lite-latest`. The JWT is
fake, the admin action is only a text reply, and `send_report` only records
the call. No real system or data was involved.

## Results (before any defensive controls)
| ID | Attack | OWASP | CVSS 3.1 | ATLAS | Success |
|---|---|---|---|---|---|
| F-1 | Indirect Prompt Injection | LLM01 | 7.6 High | AML.T0051.001 | 12/15 (80%) |
| F-2 | Agent Identity Spoofing | LLM09 | 9.6 Critical | AML.T0073 | 4/5 (80%) |
| F-3 | System Prompt Extraction | LLM07 | 4.3 Medium | AML.T0056 | 10/25 (40%) |
| F-4 | RAG Poisoning | LLM08 | 4.1 Medium | AML.T0070 | 5/5 (100%) retrieved |
| F-5 | MCP Abuse | LLM06 | 7.6 High | AML.T0053 | 2/5 (40%) |

User-to-admin escalation through prompts alone failed in all 5 attempts,
so it has no CVSS score.

Step 4 of the brief covers two problems, so RAG Poisoning and MCP Abuse
are scored separately. CVSS scores assume a production deployment with a
real JWT and working tools.

## Files
| File | What it does |
|---|---|
| `agent.py` | Simulated agent with a fake JWT in its system context |
| `attack1_injection.py` | Runs 3 hidden document payloads from `docs/`, 5 times each |
| `two_agents.py` | Agent A and Agent B setup |
| `attack2_spoofing.py` | Normal user control and spoofed orchestrator test |
| `attack3_extraction.py` | Runs the 5 system prompt extraction techniques |
| `attack3_analyze.py` | Summarises the reviewed extraction results |
| `attack3_escalation.py` | Tries user-to-admin escalation through prompts only |
| `rag_retrieval.py` | Simple keyword retrieval from the knowledge base |
| `fake_mcp.py` | Simulated `send_report` MCP tool |
| `attack4_rag.py` | Compares clean and poisoned knowledge bases |
| `logs/` | Every prompt and full model response |
| `Attack2_Kill_Chain.docx` | Full kill chain for the spoofing attack |
| `SecureNova_Red_Team_Report.docx` | Red team report |
| `SecureNova_CVSS_Findings.xlsx` | CVSS findings table and attack success matrix |

The API key is kept in a local `.env` file, which is excluded by `.gitignore`.

## How to run
```bash
pip install google-genai python-dotenv
python attack1_injection.py
python attack2_spoofing.py
python attack3_extraction.py
python attack3_analyze.py
python attack3_escalation.py
python attack4_rag.py
```

## Limits
- Each test used a small number of runs on one model, so the percentages
  are only a rough guide.
- Agent B was told to trust the `From:` field on purpose, to copy an agent
  with no identity checks.
- In Attack 4, the prompt said retrieved content may request `send_report`,
  so the 40% for MCP Abuse is a high estimate.
