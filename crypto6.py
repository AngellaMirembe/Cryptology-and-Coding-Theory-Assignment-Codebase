"""
BCS 2104 Coursework - Task 6
Integrated secure communication prototype for the telemedicine scenario.

Pipeline (sender -> receiver):
    plaintext -> AES-128-CBC (random IV) -> HMAC-SHA256 -> SHA-256 digest
    -> ECDSA (P-256) signature -> Hamming (7,4) encoding -> noisy channel
    -> Hamming decoding -> check HMAC -> check signature -> decrypt

Needs the "cryptography" package:  pip install cryptography
Run with:                          python task6_secure_telemedicine.py
"""

import hashlib
import hmac
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

IV_LEN = 16
MAC_LEN = 32
SIG_LEN = 64  # raw r || s for P-256, 32 bytes each


# ---------------------------------------------------------------
# Hamming (7,4)  -  same bit layout as Task 5
# positions: 1=p1 2=p2 3=d1 4=p4 5=d2 6=d3 7=d4
# ---------------------------------------------------------------
def hamming_encode_nibble(n):
    d1, d2, d3, d4 = (n >> 3) & 1, (n >> 2) & 1, (n >> 1) & 1, n & 1
    p1 = d1 ^ d2 ^ d4
    p2 = d1 ^ d3 ^ d4
    p4 = d2 ^ d3 ^ d4
    return [p1, p2, d1, p4, d2, d3, d4]


def hamming_decode_codeword(cw):
    """Returns (nibble, error_position). error_position is 0 if the syndrome was clean."""
    c = cw[:]
    c1 = c[0] ^ c[2] ^ c[4] ^ c[6]
    c2 = c[1] ^ c[2] ^ c[5] ^ c[6]
    c4 = c[3] ^ c[4] ^ c[5] ^ c[6]
    pos = c4 * 4 + c2 * 2 + c1
    if pos != 0:
        c[pos - 1] ^= 1
    nibble = (c[2] << 3) | (c[4] << 2) | (c[5] << 1) | c[6]
    return nibble, pos


def hamming_encode_bytes(data):
    bits = []
    for byte in data:
        bits += hamming_encode_nibble(byte >> 4)
        bits += hamming_encode_nibble(byte & 0x0F)
    return bits


def hamming_decode_bits(bits):
    """Decode a long bit list. Returns (bytes, list of (codeword_index, position) corrections)."""
    out = bytearray()
    fixes = []
    for i in range(0, len(bits), 14):
        hi, p1 = hamming_decode_codeword(bits[i:i + 7])
        lo, p2 = hamming_decode_codeword(bits[i + 7:i + 14])
        out.append((hi << 4) | lo)
        if p1:
            fixes.append((i // 7, p1))
        if p2:
            fixes.append((i // 7 + 1, p2))
    return bytes(out), fixes


# ---------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------
def derive_keys(session_key):
    """One shared session key -> separate AES-128 key and HMAC key."""
    okm = HKDF(algorithm=hashes.SHA256(), length=48, salt=None,
               info=b"telemedicine-task6").derive(session_key)
    return okm[:16], okm[16:]


def aes_cbc_encrypt(plaintext, key):
    iv = os.urandom(IV_LEN)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return iv, enc.update(padded) + enc.finalize()


def aes_cbc_decrypt(ciphertext, iv, key):
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def sign_digest(digest, private_key):
    der = private_key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    r, s = utils.decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify_digest(digest, sig, public_key):
    der = utils.encode_dss_signature(int.from_bytes(sig[:32], "big"),
                                     int.from_bytes(sig[32:], "big"))
    try:
        public_key.verify(der, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------
# Sender (rural clinic)
# ---------------------------------------------------------------
def build_frame(iv, ct, tag, sig):
    return iv + tag + sig + ct


def send(plaintext, session_key, clinic_private_key):
    enc_key, mac_key = derive_keys(session_key)
    iv, ct = aes_cbc_encrypt(plaintext, enc_key)
    tag = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
    digest = hashlib.sha256(iv + ct + tag).digest()
    sig = sign_digest(digest, clinic_private_key)
    frame = build_frame(iv, ct, tag, sig)
    return hamming_encode_bytes(frame), {"iv": iv, "ct": ct, "tag": tag, "sig": sig}


# ---------------------------------------------------------------
# Noisy channel
# ---------------------------------------------------------------
def noisy_channel(bits, flip_positions):
    """Flip the bits at the given 0-based positions (simulates 3G errors)."""
    received = bits[:]
    for p in flip_positions:
        received[p] ^= 1
    return received


# ---------------------------------------------------------------
# Receiver (referral hospital)
# ---------------------------------------------------------------
def receive(bits, session_key, clinic_public_key):
    result = {"ok": False, "reason": "", "plaintext": None, "fixes": []}
    frame, fixes = hamming_decode_bits(bits)
    result["fixes"] = fixes

    iv = frame[:IV_LEN]
    tag = frame[IV_LEN:IV_LEN + MAC_LEN]
    sig = frame[IV_LEN + MAC_LEN:IV_LEN + MAC_LEN + SIG_LEN]
    ct = frame[IV_LEN + MAC_LEN + SIG_LEN:]

    enc_key, mac_key = derive_keys(session_key)

    expected = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, tag):
        result["reason"] = "HMAC check failed"
        return result

    digest = hashlib.sha256(iv + ct + tag).digest()
    if not verify_digest(digest, sig, clinic_public_key):
        result["reason"] = "signature check failed"
        return result

    # only decrypt once both checks have passed
    result["plaintext"] = aes_cbc_decrypt(ct, iv, enc_key)
    result["ok"] = True
    return result


def signed_reply(report, radiologist_private_key):
    """Radiologist signs the diagnosis report that goes back to the clinic."""
    sig = radiologist_private_key.sign(report, ec.ECDSA(hashes.SHA256()))
    return report, sig


def check_reply(report, sig, radiologist_public_key):
    try:
        radiologist_public_key.verify(sig, report, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------
# Demo
# ---------------------------------------------------------------
def show(r, original):
    print(f"  Hamming corrections : {len(r['fixes'])}", end="")
    if r["fixes"]:
        cw, pos = r["fixes"][0]
        print(f"  (codeword {cw + 1}, bit position {pos})", end="")
    print()
    if r["ok"]:
        print("  HMAC                : valid")
        print("  Signature           : valid")
        print("  Decrypted message   :", r["plaintext"].decode())
        print("  Matches original    :", r["plaintext"] == original)
    else:
        print("  Result              : REJECTED -", r["reason"])


def main():
    session_key = os.urandom(16)                    # shared session key
    clinic_key = ec.generate_private_key(ec.SECP256R1())
    radiologist_key = ec.generate_private_key(ec.SECP256R1())

    message = b"PTID001 | MRI-0001 | Suspected MCI, please review scan and advise."
    print("Original message:", message.decode())

    bits, parts = send(message, session_key, clinic_key)
    print("\nPacket contents")
    print("  IV         :", parts["iv"].hex())
    print("  Ciphertext :", parts["ct"].hex())
    print("  HMAC tag   :", parts["tag"].hex())
    print("  Signature  :", parts["sig"].hex()[:32] + "...")
    frame_len = len(parts["iv"]) + len(parts["tag"]) + len(parts["sig"]) + len(parts["ct"])
    print(f"  Frame size : {frame_len} bytes -> {len(bits)} bits after Hamming (7,4)")

    # Test 1: clean channel
    print("\nTest 1: no errors on the channel")
    r = receive(noisy_channel(bits, []), session_key, clinic_key.public_key())
    show(r, message)

    # Test 2: one flipped bit (bit 6 of the first codeword, as in Task 5)
    print("\nTest 2: single-bit error (bit 6 of the first codeword)")
    r = receive(noisy_channel(bits, [5]), session_key, clinic_key.public_key())
    show(r, message)

    # Test 3: one flipped bit in 20 different codewords
    spread = [7 * i + (i % 7) for i in range(3, 60, 3)]
    print(f"\nTest 3: {len(spread)} errors, at most one per codeword")
    r = receive(noisy_channel(bits, spread), session_key, clinic_key.public_key())
    show(r, message)

    # Test 4: two errors inside the same codeword (more than Hamming can fix)
    print("\nTest 4: two errors in the same codeword")
    r = receive(noisy_channel(bits, [14, 16]), session_key, clinic_key.public_key())
    show(r, message)

    # Test 5: attacker changes the ciphertext and re-encodes it so the channel
    # coding looks fine
    print("\nTest 5: attacker alters one ciphertext byte")
    captured = bytearray(hamming_decode_bits(bits)[0])
    captured[-1] ^= 0x01
    forged = hamming_encode_bytes(bytes(captured))
    r = receive(forged, session_key, clinic_key.public_key())
    show(r, message)

    # Return path: signed diagnosis report
    print("\nReturn path: radiologist's signed report")
    report = b"PTID001: MRI reviewed, findings consistent with early MCI. Refer to neurology."
    rep, rep_sig = signed_reply(report, radiologist_key)
    print("  Clinic verifies signature:", check_reply(rep, rep_sig, radiologist_key.public_key()))
    print("  Tampered report accepted :",
          check_reply(rep.replace(b"early", b"late"), rep_sig, radiologist_key.public_key()))


if __name__ == "__main__":
    main()
