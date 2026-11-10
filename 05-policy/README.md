# Project 5 – Policy and Compliance

## Goal
Document the SecureNova AI identity security policy and the compliance mapping evidence used to track the project controls and remaining gaps.

## Files
- `SecureNova AI Identity Security Policy.docx` — policy with three main sections: Identity Lifecycle, Credential Governance, Incident Response Playbook.
- `SecureNova_Compliance_Mapping.xlsx` — tabs: NIST AI RMF, OWASP LLM Top 10, Compliance Gaps.

## Policy
The policy reviews every 30 or 90 days. Credentials are rotated at least every 90 days. Credentials are revoked within 24 hours on decommission. There are no long-lived credentials for agents.

The Incident Response Playbook includes three scenarios: leaked LLM API key, compromised agent identity, and prompt injection leading to data exfiltration. Each scenario includes detection signals, containment, evidence preservation, notification, and recovery.

## Compliance
Project 1-4 controls are mapped to Govern, Map, Measure, and Manage with evidence files. The OWASP mapping includes LLM01, LLM06, LLM07, and LLM09 mapped to Project 3 attacks and Project 4 controls, plus LLM08 as an extra row.

## Gaps still open
- Signed agent messages can be replayed.
- `send_report` runs without human approval.
- Private key and API keys are not in a secrets manager.

## Screenshots
- `P5_01_policy_title_toc.png`
- `P5_02_ir_playbook_scenario.png`
- `P5_03_nist_ai_rmf_tab.png`
- `P5_04_owasp_llm_top10_tab.png`
