import hashlib
import hmac
secret_key = b"my_secret_key_123"
message = b"Patient: John Doe, Diagnosis: MCI."
hmac_result = hmac.new(secret_key, message, hashlib.sha256).hexdigest()
print("HMAC-SHA256:", hmac_result)