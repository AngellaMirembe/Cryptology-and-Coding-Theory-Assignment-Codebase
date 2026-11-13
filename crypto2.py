from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

# 128-bit key (16 bytes)
key = get_random_bytes(16)
# 128-bit block representing patient record data (must be 16 bytes)
# Example: "PATIENT_REC_0001" is 16 ASCII bytes (one AES block). PKCS#7 padding adds a full block when the input is already block-aligned.
plaintext = b"PATIENT_REC_0001"

# Create AES cipher in CBC mode with a random Initialization Vector (IV)
cipher = AES.new(key, AES.MODE_CBC)
iv = cipher.iv
ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

print(f"Key (Hex): {key.hex()}")
print(f"IV  (Hex): {iv.hex()}")
print(f"Ciphertext (Hex): {ciphertext.hex()}")
