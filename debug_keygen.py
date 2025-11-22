
import logging
from app.services.ssh.keys import generate_ssh_key

logging.basicConfig(level=logging.DEBUG)

print("Testing RSA generation...")
try:
    priv, pub = generate_ssh_key('rsa')
    print(f"✅ RSA Success. Pub: {pub[:30]}...")
except Exception as e:
    print(f"❌ RSA Failed: {e}")

print("\nTesting Ed25519 generation...")
try:
    priv, pub = generate_ssh_key('ed25519')
    print(f"✅ Ed25519 Success. Pub: {pub[:30]}...")
    print(f"Private key starts with: {priv.splitlines()[0]}")
except Exception as e:
    print(f"❌ Ed25519 Failed: {e}")
