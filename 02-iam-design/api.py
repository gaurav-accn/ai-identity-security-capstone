import os
import jwt
from jwt import PyJWKClient
from fastapi import FastAPI, Depends, HTTPException, Header
from dotenv import load_dotenv

load_dotenv()
# Load the Auth0 metadata once so every request validates the same issuer and audience.
DOMAIN = os.environ["AUTH0_DOMAIN"]
AUDIENCE = os.environ["API_AUDIENCE"]
ISSUER = f"https://{DOMAIN}/"

# Auth0's public keys, used to check the RS256 signature
jwks_client = PyJWKClient(f"{ISSUER}.well-known/jwks.json")

app = FastAPI(title="SecureNova AI API")

# Check the Authorization header, validate the JWT signature, and reject expired or invalid tokens before any API logic runs.
def verify_token(authorization: str = Header(default=None)) -> dict:
    """401 if there is no token, or it is fake, expired, or for another API."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing bearer token")
    token = authorization.split(" ", 1)[1]
    try:
        key = jwks_client.get_signing_key_from_jwt(token).key
        return jwt.decode(token, key, algorithms=["RS256"],
                          audience=AUDIENCE, issuer=ISSUER)
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except jwt.PyJWTError as e:
        raise HTTPException(401, f"Invalid token: {e}")

# Enforce RBAC by checking the token's granted scopes or permissions before allowing a protected action.
def require_scope(scope: str):
    """403 if the token is valid but lacks the needed scope."""
    def checker(claims: dict = Depends(verify_token)):
        granted = set(claims.get("scope", "").split()) | set(claims.get("permissions", []))
        if scope not in granted:
            raise HTTPException(403, f"Missing scope: {scope}")
        return claims
    return checker

# Protect the chat route with the data-read scope so only authorized callers can use the AI API.
@app.post("/chat")
def chat(claims: dict = Depends(require_scope("read:ai-data"))):
    return {"reply": "Hello from SecureNova AI", "user": claims["sub"]}

# Keep the admin route separate and require the stronger write permission to reduce the risk of privilege escalation.
@app.post("/admin")
def admin(claims: dict = Depends(require_scope("write:admin"))):
    return {"status": "admin action done", "user": claims["sub"]}