# Project 5 – Policy and Compliance

## Goal
Turn the work from Projects 1–4 into a written security policy for AI agent
identities, check the controls against NIST AI RMF and the OWASP LLM Top 10,
and explain the risks and next steps to a non-technical CTO.

## Files
| File | What it is |
|---|---|
| `SecureNova AI Identity Security Policy.docx` | Policy with three main sections: Identity Lifecycle, Credential Governance and the Incident Response Playbook |
| `SecureNova_Compliance_Mapping.xlsx` | Three tabs: NIST AI RMF, OWASP LLM Top 10 and Compliance Gaps |
| `SecureNova Security Walkthrough.docx` | Walkthrough for the CTO: scope and methodology, risk priority matrix and top 5 recommendations |

## Policy
| Section | What it sets |
|---|---|
| Identity Lifecycle | Agent identities are reviewed every 30 days if they have admin or write access, and every 90 days if they are read-only. Credentials are revoked within 24 hours when an agent is retired. |
| Credential Governance | API keys, client secrets and signing keys are rotated at least every 90 days. Long-lived credentials are not allowed for agents, and no credential may be placed in the model's context. |
| Incident Response Playbook | Three scenarios: leaked LLM API key, compromised agent identity, and prompt injection leading to data exfiltration. Each has detection signals, containment, evidence preservation, notification and recovery steps. |

The detection signals in the playbook come from the Project 4 rules: volume
spike, scope change, token reuse, signature failure and JWT redaction.

## Compliance mapping
- **NIST AI RMF:** each Project 1–4 control is mapped to Govern, Map, Measure
  or Manage, with the file that proves it.
- **OWASP LLM Top 10:** LLM01, LLM06, LLM07 and LLM09 are mapped to the
  Project 3 attack and the Project 4 control. LLM08 (F-4, RAG poisoning) is
  added as an extra row so every finding is covered.

## Gaps still open
| Gap | Why it matters |
|---|---|
| Signed agent messages can be replayed | A captured valid message could make Agent B run the action again |
| `send_report` runs without human approval | A new injection that the guardrail misses could still send data out |
| Private key and API keys are not in a secrets manager | Anyone with access to the Codespace could copy them |

## Walkthrough for the CTO
Written in plain language, without technical terms.

- **Risk priority matrix:** the 5 findings plotted by how often the attack
  worked and how serious it would be, with the CVSS score on each. F-2 (9.6)
  and F-1 (7.6) are both likely and serious, so they come first.
- **Top 5 recommendations:**

| # | Recommendation | Fixes | Effort |
|---|---|---|---|
| 1 | Time stamp and one-time ID on every agent message | F-2, gap 1 | 2–3 days |
| 2 | Keep login tokens out of what the AI can read | F-1 | About 1 week |
| 3 | Human approval before data is sent outside | F-5, gap 2 | About 1 week |
| 4 | Keys in a secrets store, rotated every 90 days | Gap 3 | 1–2 weeks |
| 5 | Approve documents before they reach the AI, and tune the filter | F-4, F-3 | 1–2 weeks, then ongoing |

The business reason for each one is in the walkthrough document.

## Screenshots
| # | File | Shows |
|---|---|---|
| 1 | `P5_01_policy_title_toc.png` | Policy title page and table of contents |
| 2 | `P5_02_ir_playbook_scenario.png` | IR Playbook scenario with detection signals and containment |
| 3 | `P5_03_nist_ai_rmf_tab.png` | NIST AI RMF tab |
| 4 | `P5_04_owasp_llm_top10_tab.png` | OWASP LLM Top 10 tab |
| 5 | `P5_05_github_repo_folders.png` | Repository with all five project folders |
| 6 | `P5_06_github_commit_history.png` | Contributor graph across the project days |
| 7 | `P5_07_risk_priority_matrix.png` | Risk priority matrix with all 5 findings and CVSS scores |
| 8 | `P5_08_top5_recommendations.png` | Top 5 recommendations with effort and business reason |

## Notes
- This folder has no code. The policy, spreadsheet and walkthrough are based
  on the results already in Projects 1–4.
- LLM09 is the label the brief gives for agent spoofing (F-2). In the 2025
  list LLM09 is Misinformation, so the spreadsheet explains this choice.
