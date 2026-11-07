import os, secrets, hashlib, base64, json
from urllib.parse import urlencode, urlparse, parse_qs
import requests
from dotenv import load_dotenv

load_dotenv()
DOMAIN = os.environ["AUTH0_DOMAIN"]
CLIENT_ID = os.environ["WEB_CLIENT_ID"]
CLIENT_SECRET = os.environ["WEB_CLIENT_SECRET"]
AUDIENCE = os.environ["API_AUDIENCE"]
REDIRECT_URI = "http://localhost:8000/callback"

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

# 1. PKCE: random secret (verifier) and its SHA-256 hash (challenge)
code_verifier = b64url(secrets.token_bytes(32))
code_challenge = b64url(hashlib.sha256(code_verifier.encode()).digest())
state = secrets.token_urlsafe(16)

print("PKCE code_verifier :", code_verifier[:12] + "...")
print("PKCE code_challenge:", code_challenge)

# 2. Login URL. We deliberately ASK for write:admin too, to prove RBAC strips it.
params = {
    "response_type": "code",
    "client_id": CLIENT_ID,
    "redirect_uri": REDIRECT_URI,
    "audience": AUDIENCE,
    "scope": "openid profile email read:ai-data write:admin",
    "code_challenge": code_challenge,
    "code_challenge_method": "S256",
    "state": state,
}
print("\nOpen this URL in your browser and log in:\n")
print(f"https://{DOMAIN}/authorize?" + urlencode(params))

# 3. After login, the browser goes to localhost:8000/callback?code=...
redirected = input("\nPaste the FULL URL from the browser address bar: ").strip()
qs = parse_qs(urlparse(redirected).query)
if qs.get("state", [None])[0] != state:
    raise SystemExit("State mismatch: possible CSRF, stopping.")
code = qs["code"][0]

# 4. Exchange code + verifier for the token
resp = requests.post(f"https://{DOMAIN}/oauth/token", data={
    "grant_type": "authorization_code",
    "client_id": CLIENT_ID,
    "client_secret": CLIENT_SECRET,
    "code": code,
    "code_verifier": code_verifier,
    "redirect_uri": REDIRECT_URI,
})
resp.raise_for_status()
access_token = resp.json()["access_token"]
open("token.txt", "w").write(access_token)

# 5. Show what Auth0 actually granted
payload = json.loads(base64.urlsafe_b64decode(access_token.split(".")[1] + "=="))
print("\nToken saved to token.txt")
print("aud        :", payload["aud"])
print("scope      :", payload.get("scope"))
print("permissions:", payload.get("permissions"))