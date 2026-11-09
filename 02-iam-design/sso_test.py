import os, secrets, hashlib, base64, json
from datetime import datetime
from urllib.parse import urlencode, urlparse, parse_qs
import requests
from dotenv import load_dotenv

load_dotenv()
DOMAIN = os.environ["AUTH0_DOMAIN"]
CLIENT_ID = os.environ["HELP_CLIENT_ID"]          # second app: SecureNova Help Portal
CLIENT_SECRET = os.environ["HELP_CLIENT_SECRET"]
REDIRECT_URI = "http://localhost:9000/callback"

def b64url(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def claims(jwt): return json.loads(base64.urlsafe_b64decode(jwt.split(".")[1] + "=="))
def ts(): return datetime.now().strftime("%H:%M:%S")

verifier = b64url(secrets.token_bytes(32))
challenge = b64url(hashlib.sha256(verifier.encode()).digest())
state = secrets.token_urlsafe(16)

print(f"[{ts()}] SSO test: second client = SecureNova Help Portal")
print("Open this URL in the SAME browser window where you logged in to the Chat Web App:\n")
print(f"https://{DOMAIN}/authorize?" + urlencode({
    "response_type": "code", "client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI,
    "scope": "openid profile email", "code_challenge": challenge,
    "code_challenge_method": "S256", "state": state}))

url = input("\nPaste the FULL callback URL: ").strip()
qs = parse_qs(urlparse(url).query)
if qs.get("state", [None])[0] != state:
    raise SystemExit("State mismatch, stopping.")

r = requests.post(f"https://{DOMAIN}/oauth/token", data={
    "grant_type": "authorization_code", "client_id": CLIENT_ID,
    "client_secret": CLIENT_SECRET, "code": qs["code"][0],
    "code_verifier": verifier, "redirect_uri": REDIRECT_URI})
r.raise_for_status()
help_id = claims(r.json()["id_token"])
chat_id = claims(open("id_token.txt").read())       # saved by login_pkce.py

print(f"\n[{ts()}] Chat Web App  ID token: sub={chat_id['sub']}  sid={chat_id.get('sid')}  aud={chat_id['aud']}")
print(f"[{ts()}] Help Portal   ID token: sub={help_id['sub']}  sid={help_id.get('sid')}  aud={help_id['aud']}")
print(f"[{ts()}] Same user: {chat_id['sub'] == help_id['sub']}   Same SSO session: {chat_id.get('sid') == help_id.get('sid')}")