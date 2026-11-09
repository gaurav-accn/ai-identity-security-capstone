"""Generate the Ed25519 key pair that proves Agent A's identity."""
import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

KEY_DIR = Path(__file__).resolve().parent / "keys"
PRIVATE_FILE = KEY_DIR / "agent_private.pem"
PUBLIC_FILE = KEY_DIR / "agent_public.pem"


def main():
    if PRIVATE_FILE.exists() or PUBLIC_FILE.exists():
        raise SystemExit("Keys already exist. Delete the keys folder to create a new pair.")

    KEY_DIR.mkdir(exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    PRIVATE_FILE.write_bytes(private_bytes)
    os.chmod(PRIVATE_FILE, 0o600)  # only the file owner can read the private key
    PUBLIC_FILE.write_bytes(public_bytes)

    print("Ed25519 key pair generated with Python cryptography")
    print(f"Private key : keys/{PRIVATE_FILE.name}")
    print(f"Public key  : keys/{PUBLIC_FILE.name}")
    print(f"Public key SHA-256: {hashlib.sha256(public_bytes).hexdigest()}")


if __name__ == "__main__":
    main()