import os, secrets, hashlib, base64, json
from datetime import datetime
from urllib.parse import urlencode, urlparse, parse_qs
import requests
from dotenv import load_dotenv

load_dotenv()
# Read the second app's credentials so the SSO check runs against the Help Portal instead of the chat client.
DOMAIN = os.environ["AUTH0_DOMAIN"]
CLIENT_ID = os.environ["HELP_CLIENT_ID"]          # second app: SecureNova Help Portal
CLIENT_SECRET = os.environ["HELP_CLIENT_SECRET"]
REDIRECT_URI = "http://localhost:9000/callback"

# Encode random bytes in the same URL-safe form used by the original PKCE flow for consistency.
def b64url(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def claims(jwt): return json.loads(base64.urlsafe_b64decode(jwt.split(".")[1] + "=="))
def ts(): return datetime.now().strftime("%H:%M:%S")

# Build a fresh PKCE verifier and challenge for the second client so the login is bound to the same browser session.
verifier = b64url(secrets.token_bytes(32))
challenge = b64url(hashlib.sha256(verifier.encode()).digest())
state = secrets.token_urlsafe(16)

# Open the second login request in the same browser session to verify whether both apps share the same Auth0 SSO session.
print(f"[{ts()}] SSO test: second client = SecureNova Help Portal")
print("Open this URL in the SAME browser window where you logged in to the Chat Web App:\n")
print(f"https://{DOMAIN}/authorize?" + urlencode({
    "response_type": "code", "client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI,
    "scope": "openid profile email", "code_challenge": challenge,
    "code_challenge_method": "S256", "state": state}))

url = input("\nPaste the FULL callback URL: ").strip()
# Validate that the callback preserves the same state value so the second login cannot be replayed from another browser flow.
qs = parse_qs(urlparse(url).query)
if qs.get("state", [None])[0] != state:
    raise SystemExit("State mismatch, stopping.")

# Exchange the authorization code for the help-portal token so the second app can provide its own ID token for SSO comparison.
r = requests.post(f"https://{DOMAIN}/oauth/token", data={
    "grant_type": "authorization_code", "client_id": CLIENT_ID,
    "client_secret": CLIENT_SECRET, "code": qs["code"][0],
    "code_verifier": verifier, "redirect_uri": REDIRECT_URI})
r.raise_for_status()
# Decode both ID tokens and compare their subject/session claims to determine whether the browser has a shared SSO session.
help_id = claims(r.json()["id_token"])
chat_id = claims(open("id_token.txt").read())       # saved by login_pkce.py

print(f"\n[{ts()}] Chat Web App  ID token: sub={chat_id['sub']}  sid={chat_id.get('sid')}  aud={chat_id['aud']}")
print(f"[{ts()}] Help Portal   ID token: sub={help_id['sub']}  sid={help_id.get('sid')}  aud={help_id['aud']}")
print(f"[{ts()}] Same user: {chat_id['sub'] == help_id['sub']}   Same SSO session: {chat_id.get('sid') == help_id.get('sid')}")