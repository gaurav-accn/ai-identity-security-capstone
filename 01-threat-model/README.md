# Project 1 – Threat Model of the AI Identity System

## Goal
Find every identity in the SecureNova AI platform, see where an attacker
could misuse it, and decide which risks to fix first.

## What I did
1. **Identity inventory** – listed the 6 identities (human user, AI agent,
   OAuth M2M client, LLM API key, RAG service, MCP server) with how each
   one logs in and how much power it has.
2. **Data-flow diagram** – drew how one customer request moves through the
   system in OWASP Threat Dragon, with 5 trust boundaries.
3. **STRIDE** – added 3 threats to one identity flow in Threat Dragon, then
   applied all 6 STRIDE categories to all 10 identity flows in a matrix.
4. **Attack trees** – built 3 trees in draw.io and scored each path as
   Likelihood × Impact.
5. **Risk register** – combined everything into 15 risks, ranked by score,
   each with a MITRE ATLAS ID and an owner.

## Files
| File | What it is |
|---|---|
| `SecureNova_Threat_Model.xlsx` | Identity Inventory, STRIDE Matrix, Risk Register, ATLAS Mapping |
| `../ThreatDragonModels/SecureNova AI Platform/` | Threat Dragon model (diagram + threats) |
| `attack-tree-1-llm-key.drawio` | Attack tree 1 – steal the LLM API key |
| `attack-tree-2-agent-spoofing.drawio` | Attack tree 2 – pretend to be the AI agent |
| `attack-tree-3-rag-poisoning.drawio` | Attack tree 3 – poison the RAG knowledge base |

## Screenshots
| # | Screenshot |
|---|---|
| 1 | `screenshot-01-dfd.png` – data-flow diagram with trust boundaries |
| 2 | `screenshot-02-threats.png` – 3 STRIDE threats on flow 3 |
| 3 | `screenshot-03-attack-tree-1.png` – LLM API key exfiltration |
| 4 | `screenshot-04-attack-tree-2.png` – agent identity spoofing |
| 5 | `screenshot-05-attack-tree-3.png` – RAG chunk poisoning |
| 6 | `screenshot-06-strideMatrix-a.png`, `-b.png` – full STRIDE matrix |
| 7 | `screenshot-07-risk-register.png` – ranked risk register |
| 8 | `screenshot-08-atlas.png` – MITRE ATLAS AML.T0070 page |

## Attack trees → MITRE ATLAS
| Tree | Root risk | ATLAS ID |
|---|---|---|
| 1. LLM API key exfiltration | 20 (High) | AML.T0055 Unsecured Credentials |
| 2. Agent identity spoofing | 16 (High) | AML.T0073 Impersonation |
| 3. RAG chunk poisoning | 16 (High) | AML.T0070 RAG Poisoning |

## Top 3 risks
1. **LLM API key committed to GitHub (20)** – keep keys in `.env` or a vault,
   turn on secret scanning, rotate keys.
2. **Prompt injection makes the agent act for the attacker (16)** – check
   permissions inside every tool and pass the user's identity with each call.
3. **Poisoned documents in the knowledge base (16)** – read-only RAG access,
   approve documents before adding them, treat retrieved text as data.

## Main finding
The biggest risks come from **how keys are handled** and from **the agent
trusting text it reads**, not from advanced hacking.
