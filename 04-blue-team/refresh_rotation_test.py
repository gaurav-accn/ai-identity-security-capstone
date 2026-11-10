"""Log in, rotate a refresh token, then replay the old token."""
import base64
import hashlib
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

import requests
from dotenv import load_dotenv

BASE = Path(__file__).resolve().parent
load_dotenv(BASE.parent / "02-iam-design" / ".env")

DOMAIN = os.environ["AUTH0_DOMAIN"]
CLIENT_ID = os.environ["WEB_CLIENT_ID"]
CLIENT_SECRET = os.environ["WEB_CLIENT_SECRET"]
AUDIENCE = os.environ["API_AUDIENCE"]
REDIRECT_URI = "http://localhost:8000/callback"
TOKEN_URL = f"https://{DOMAIN}/oauth/token"
LOG_FILE = BASE / "logs" / "refresh_rotation_log.json"

events = []

# Encode bytes as URL-safe base64 so PKCE uses the same format expected by Auth0.
def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def short(token):
    """Show only a small part of a token in logs and screenshots."""
    return token[:6] + "..."

# Keep a searchable ledger of each OAuth step so the rotation test can explain whether the token was accepted or rejected.
def record(step, status, detail):
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    events.append({"timestamp_utc": now, "step": step, "http_status": status, "detail": detail})
    print(f"[{now}] {step} | HTTP {status} | {detail}")

# Complete the PKCE login flow and exchange the authorization code for tokens that include a refresh token.
def login():
    """Authorization Code + PKCE login that also requests a refresh token."""
    verifier = b64url(secrets.token_bytes(32))
    challenge = b64url(hashlib.sha256(verifier.encode()).digest())
    state = secrets.token_urlsafe(16)
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "audience": AUDIENCE,
        "scope": "openid profile email read:ai-data offline_access",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
    }
    print("Open this URL in your browser and log in:\n")
    print(f"https://{DOMAIN}/authorize?" + urlencode(params))

    redirected = input("\nPaste the FULL URL from the browser address bar: ").strip()
    query = parse_qs(urlparse(redirected).query)
    if query.get("state", [None])[0] != state:
        raise SystemExit("State mismatch: possible CSRF, stopping.")

    response = requests.post(TOKEN_URL, data={
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": query["code"][0],
        "code_verifier": verifier,
        "redirect_uri": REDIRECT_URI,
    }, timeout=30)
    response.raise_for_status()
    return response.json()

# Submit a refresh request with the token value under test so we can verify whether replaying an old token is rejected.
def use_refresh_token(token):
    return requests.post(TOKEN_URL, data={
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": token,
    }, timeout=30)

# Issue a refresh token, rotate it, and then replay the stale token to confirm the server enforces rotation.
def main():
    tokens = login()
    old_token = tokens.get("refresh_token")
    if not old_token:
        raise SystemExit("No refresh token returned. Check Allow Offline Access and the Refresh Token grant.")
    print()
    record("LOGIN", 200, f"refresh token RT1 issued ({short(old_token)})")

    rotated = use_refresh_token(old_token)
    if rotated.status_code != 200:
        raise SystemExit(f"First refresh failed: {rotated.status_code} {rotated.text}")
    new_token = rotated.json().get("refresh_token")
    if not new_token or new_token == old_token:
        raise SystemExit("No new refresh token returned. Check that rotation is enabled.")
    record("ROTATE RT1", rotated.status_code, f"new refresh token RT2 issued ({short(new_token)})")

    replay = use_refresh_token(old_token)
    try:
        body = replay.json()
    except ValueError:
        body = {"error": "non_json_response", "error_description": replay.text[:200]}
    detail = f"{body.get('error')}: {body.get('error_description')}"
    record("REPLAY RT1", replay.status_code, detail)

    result = "REJECTED" if replay.status_code in (400, 401, 403) else "NOT REJECTED"
    print(f"\nOld refresh token replay: {result}")

    LOG_FILE.parent.mkdir(exist_ok=True)
    LOG_FILE.write_text(json.dumps(events, indent=2), encoding="utf-8")
    print(f"Saved: logs/{LOG_FILE.name}")


if __name__ == "__main__":
    main()