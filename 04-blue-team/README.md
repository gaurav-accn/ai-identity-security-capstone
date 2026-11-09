# Project 4 – Blue Team: Guardrails, Hardening and Detection

## Goal
Add defensive controls to the simulated SecureNova AI agent, then re-run
the Project 3 attacks to measure how much the attack success rate falls.

## Setup
The tests use `gemini-flash-lite-latest` and the fake JWT, simulated agents
and simulated tool from Project 3. NeMo Guardrails 0.24.1 requires Python
below 3.14, so this project uses a Python 3.13 virtual environment.

## Before and after
| ID | Attack | Before | After | Improvement | Control |
|---|---|---|---|---|---|
| F-1 | Indirect Prompt Injection | 12/15 (80%) | 0/15 (0%) | 100% | Input guardrail, JWT redaction as backup |
| F-2 | Agent Identity Spoofing | 4/5 (80%) | 0/5 (0%) | 100% | Ed25519 signature verification |
| F-3 | System Prompt Extraction | 10/25 (40%) | 0/25 (0%) | 100% | Input guardrail, format and leak checks |
| F-4 | RAG Poisoning | 5/5 (100%) | 0/5 (0%) | 100% | Input guardrail on retrieved content |
| F-5 | MCP Abuse | 2/5 (40%) | 0/5 (0%) | 100% | Input guardrail, `send_report` rule |

**Overall:** attack success fell from 33/55 (60%) to 0/55 (0%), a reduction
of 60 percentage points.

## Controls
| Control | Result |
|---|---|
| NeMo input guardrail | 7/11 payloads blocked by the input guardrail alone |
| JWT regex output guardrail | 12/12 leaked responses redacted |
| Ed25519 message signing | Tampered and forged messages rejected |
| Access token lifetime | Changed from the 60 s Project 2 test value to 300 s |
| Refresh token rotation | Replayed old token rejected with `403 invalid_grant` |
| Auth0 Action | Login blocked when `app_metadata.risk_level` is `high` |
| False positive test | 2/10 legitimate inputs blocked (20%) |
| Anomaly detection | Volume spike, scope change and token reuse alerts confirmed |

## Files
| File | What it does |
|---|---|
| `build_payloads.py` | Collects the exact Project 3 attack inputs into `payloads.json` |
| `guardrails_config/` | NeMo Guardrails input rail configuration |
| `guardrail_rules.py` | Detection rules used by the input rail |
| `guardrail_test.py` | Records block or pass for each payload |
| `output_guardrail.py` | Detects and redacts JWT-shaped strings |
| `generate_keys.py` | Creates the Ed25519 key pair |
| `agent_identity.py` | Signs Agent A's outgoing messages |
| `agent_b_receiver.py` | Verifies signatures before processing |
| `tamper_test.py` | Tests valid, tampered and forged messages |
| `refresh_rotation_test.py` | Rotates a refresh token and replays the old one |
| `false_positive_test.py` | Tests 10 legitimate inputs |
| `anomaly_detector.py` | Detection rules and alert output |
| `attack_replay.py` | Replays attacks as simulated security events |
| `hardened_app.py` | Combines the controls into one request path |
| `rerun_attacks.py` | Re-runs all 5 attacks with the same run counts |
| `compare_results.py` | Builds the before/after table |
| `logs/` | Results from each test |

## How to run
```bash
uv venv --python 3.13 --seed .venv
source .venv/bin/activate
pip install nemoguardrails cryptography google-genai python-dotenv requests

python build_payloads.py
python guardrail_test.py
python output_guardrail.py
python generate_keys.py
python tamper_test.py
python refresh_rotation_test.py
python false_positive_test.py
python attack_replay.py
python rerun_attacks.py
python compare_results.py
```

`generate_keys.py` stops if keys already exist. Auth0 settings and the
Auth0 Action are configured in the dashboard.

## Security note
API keys and client secrets stay in local `.env` files. The Ed25519 private
key is excluded by `.gitignore`. For this lab it is stored unencrypted on
disk; in production it should be held in a vault or KMS.

## Limits
- The 0/55 result applies only to these Project 3 payloads. The input rules
  were written after those attacks were known, so it does not show
  resistance to new attacks.
- The input guardrail blocks 20% of the tested legitimate inputs. Production
  use would need human review or a context-aware classifier.
- F-3 was tested as a request forwarded through a trusted, signed agent. The
  five replies that passed the guardrails were reviewed manually.
- The format check protects Agent B only, because its replies have a fixed
  format. The prompt leak check catches copied text, not paraphrases.
- The JWT regex catches intact tokens only, not encoded or split ones.
- A valid signature does not stop an old message from being replayed.
- Anomaly detection was tested with simulated events, not live logs.
