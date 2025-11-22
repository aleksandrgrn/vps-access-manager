
import paramiko
import inspect

print(f"Paramiko version: {paramiko.__version__}")

try:
    print("Checking Ed25519Key attributes:")
    print(dir(paramiko.Ed25519Key))
    
    if hasattr(paramiko.Ed25519Key, 'generate'):
        print("✅ Ed25519Key.generate exists")
        key = paramiko.Ed25519Key.generate()
        print("✅ Generated key successfully")
    else:
        print("❌ Ed25519Key.generate MISSING")
        
except Exception as e:
    print(f"❌ Error: {e}")
