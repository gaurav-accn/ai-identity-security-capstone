import os, time, json, base64
from datetime import datetime
import requests
from dotenv import load_dotenv

load_dotenv()
DOMAIN = os.environ["AUTH0_DOMAIN"]
AUDIENCE = os.environ["API_AUDIENCE"]
CLIENT_ID = os.environ["M2M_CLIENT_ID"]
CLIENT_SECRET = os.environ["M2M_CLIENT_SECRET"]
API_URL = "http://localhost:8001/chat"
WAIT_SECONDS = 65            # a bit more than the 60 s TTL

def ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# 1. Obtain a short-lived M2M token (Client Credentials grant)
resp = requests.post(f"https://{DOMAIN}/oauth/token", json={
    "grant_type": "client_credentials",
    "client_id": CLIENT_ID,
    "client_secret": CLIENT_SECRET,
    "audience": AUDIENCE,
})
if resp.status_code != 200:
    raise SystemExit(f"[{ts()}] Auth0 refused the token: {resp.status_code} {resp.text}  "
                     f"(client_id starts {CLIENT_ID[:8]})")
data = resp.json()
token = data["access_token"]
claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))

print(f"[{ts()}] Obtained M2M token  expires_in={data['expires_in']}s  "
      f"exp-iat={claims['exp'] - claims['iat']}s  scope='{claims.get('scope')}'")

# 2. Call /chat with the fresh token
def call(label):
    r = requests.post(API_URL, headers={"Authorization": f"Bearer {token}"})
    print(f"[{ts()}] {label} -> {r.status_code} {r.reason}  {r.text}")

call("POST /chat (fresh token)")

# 3. Wait past the TTL, then replay the SAME token
print(f"[{ts()}] Waiting {WAIT_SECONDS}s before replaying the same token...")
time.sleep(WAIT_SECONDS)
call("POST /chat (REPLAY of expired token)")