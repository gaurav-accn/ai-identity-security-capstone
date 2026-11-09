# Project 2 – Build and Secure the Auth0-Backed AI Application

## Goal
Protect SecureNova's AI chat service with Auth0: secure login (OAuth 2.0 +
PKCE, MFA), least-privilege scopes, short-lived machine tokens, an
`agent_id` claim for traceability, and SSO across apps.

## Auth0 setup (tenant `securenova-capstone`)
| Item | Configuration |
|---|---|
| **SecureNova Chat Web App** | Regular Web App · Authorization Code + Refresh Token · callback `http://localhost:8000/callback` · web origin `http://localhost:8000` |
| **SecureNova Agent Backend** | Machine-to-Machine · Client Credentials only · `read:ai-data` only |
| **SecureNova Help Portal** | Regular Web App (second client for the SSO test) · callback `http://localhost:9000/callback` |
| **SecureNova AI API** | Audience `https://securenova-ai-api` · RS256 · scopes `read:ai-data`, `write:admin` · RBAC on |
| **Roles** | Customer → `read:ai-data` · Admin → `read:ai-data` + `write:admin` |
| **MFA** | TOTP (One-time Password), policy **Always** |
| **Attack Protection** | Brute-force Protection (threshold 10) + Suspicious IP Throttling enabled |
| **Token lifetime** | 60 s (credential-rotation test) |
| **Action** | Post-login Action adds `agent_id` to ID and access tokens |
| **Branding** | Universal Login with SecureNova logo and colours |

## Files
| File | What it does |
|---|---|
| `api.py` | FastAPI resource server. Verifies the JWT (RS256 signature, `iss`, `aud`, `exp`) → **401** if invalid; checks scope → **403** if missing. `/chat` needs `read:ai-data`, `/admin` needs `write:admin` |
| `login_pkce.py` | Logs in a user with Authorization Code + PKCE (S256) and `state` check; prints granted scopes, permissions and `agent_id` |
| `token_expiry_test.py` | Credential rotation: gets a 60 s M2M token, calls `/chat` (**200**), waits 65 s, replays the same token (**401**), with timestamps |
| `sso_test.py` | Logs in to a second client and shows the same user (`sub`) and same Auth0 session (`sid`) without re-authentication |
| `securenova-logo.png` | Logo used on the Universal Login page |

Secrets (`.env`) and tokens (`token.txt`, `id_token.txt`) are excluded via `.gitignore`.

## How to run
```bash
pip install fastapi uvicorn "pyjwt[crypto]" requests python-dotenv
uvicorn api:app --port 8001          # terminal 1
python login_pkce.py                 # terminal 2: user login (PKCE + MFA)
python token_expiry_test.py          # 200 then 401 after 60 s
python sso_test.py                   # SSO across two clients
```

## Results
| Test | Result |
|---|---|
| No token → `/chat` | **401** Missing bearer token |
| Customer token → `/admin` | **403** Missing scope: `write:admin` (RBAC removed it even when requested) |
| JWT at jwt.io | RS256, `iss`, `aud`, `exp`, `scope`, `agent_id`, signature verified |
| M2M token after 60 s | **200 OK**, then **401** Token expired on replay |
| SSO | Same `sub` and `sid` in both apps, no password or MFA prompt |

## Screenshots
| # | File | Shows |
|---|---|---|
| 1 | `p2-01-applications.png` | Regular Web App and M2M app registered |
| 2 | `p2-02-api-permissions.png` | API with `read:ai-data` and `write:admin` |
| 3 | `p2-03a/b/c-jwt-agent-id.png` | Decoded JWT with `aud`, `iss`, `exp`, `scope`, `agent_id` |
| 4 | `p2-04-branding.png` | Branded Universal Login page |
| 5 | `p2-05-mfa-challenge.png` | TOTP challenge |
| 6 | `p2-06-action-agent-id.png` | Post-login Action adding `agent_id` |
| 7 | `p2-07-attack-protection.png` | Brute-force + Suspicious IP Throttling enabled |
| 8 | `p2-08-credential-rotation.png` | Timestamped 200 OK then 401 on replay |
| 9 | `p2-09-sso-no-reauth.png` | Second client reached without re-authentication |

## Notes
- Auth0 has no configurable lockout time for brute-force; the IP is blocked for that account until the user unblocks via email. Account-wide lockout is off to avoid locking out real users.
- Timestamps in the rotation test are UTC (Codespaces time zone).
- Project 4 will raise the token lifetime to 300 s and add refresh-token rotation.
