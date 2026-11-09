# AI Identity Security Capstone – SecureNova

SecureNova is a fictional company whose AI customer-service chatbot uses
Auth0 for login. The chatbot holds real power (tokens, API keys, tools),
so this capstone finds the identity risks, builds the controls, attacks
them, fixes the gaps, and writes the policy.

## Projects
| # | Folder | Project | Status |
|---|---|---|---|
| 1 | [`01-threat-model`](01-threat-model) | Threat model: identity inventory, Threat Dragon DFD + STRIDE, 3 attack trees, risk register with MITRE ATLAS IDs | ✅ Done |
| 2 | [`02-iam-design`](02-iam-design) | Auth0 implementation: PKCE, scopes + RBAC (403 test), MFA, attack protection, 60 s credential rotation, `agent_id` Action, SSO, branding | ✅ Done |
| 3 | [`03-red-team`](03-red-team) | Red team: prompt injection, agent spoofing, system prompt extraction, RAG poisoning, MCP abuse, CVSS + ATLAS | ✅ Done |
| 4 | [`04-blue-team`](04-blue-team) | Blue team: guardrails, JWT redaction, Ed25519 message signing, Auth0 hardening, anomaly detection, before/after comparison | ✅ Done |
| 5 | [`05-policy`](05-policy) | Security policy, NIST AI RMF + OWASP LLM Top 10 compliance, presentation | ⏳ |

`ThreatDragonModels/` holds the OWASP Threat Dragon model used in Project 1.

## Tools
Auth0 · Python (FastAPI, PyJWT, requests, cryptography) · NeMo Guardrails ·
Google Gemini API · GitHub Codespaces · OWASP Threat Dragon · draw.io ·
jwt.io · MITRE ATLAS

## Security note
No secrets are stored in this repo. Credentials live in local `.env` files,
test tokens in `token.txt` / `id_token.txt`, and the Ed25519 private key in
`*_private.pem`, all excluded by `.gitignore`.
