from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
# Generate receiver's P-256 key pair
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

# Generate sender's temporary key pair
ephemeral = ec.generate_private_key(ec.SECP256R1())
# Generate shared secret
secret = ephemeral.exchange(ec.ECDH(), public_key)
# Derive encryption key
key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"ECIES"
).derive(secret)
# Encrypt message
message = b"Patient medical report"
nonce = os.urandom(12)
cipher = AESGCM(key)
encrypted = cipher.encrypt(nonce, message, None)
# Receiver derives the same key
shared = private_key.exchange(
    ec.ECDH(), ephemeral.public_key())
receiver_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"ECIES"
).derive(shared)
# Decrypt message
decrypted = AESGCM(receiver_key).decrypt(
    nonce, encrypted, None)
print("Encrypted:", encrypted.hex())
print("Decrypted:", decrypted.decode())