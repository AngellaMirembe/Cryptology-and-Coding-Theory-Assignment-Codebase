alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
message = "THE DOCTOR WILL CHECK THE PATIENT"
cipher = ""

# Encrypt each letter with a Caesar shift of 3; keep spaces unchanged.
for letter in message:
    if letter in alphabet:
        position = alphabet.index(letter)
        cipher += alphabet[(position + 3) % 26]
    else:
        cipher += letter

print("Encrypted message:", cipher)

# Count letters and identify the most frequent encrypted letter.
letters = [letter for letter in cipher if letter in alphabet]
most_common = max(set(letters), key=letters.count)
print("Most common encrypted letter:", most_common)

# Estimate the shift by assuming the most common letter represents E.
shift = (alphabet.index(most_common) - alphabet.index("E")) % 26

# Decrypt using the estimated shift.
plain = ""
for letter in cipher:
    if letter in alphabet:
        position = alphabet.index(letter)
        plain += alphabet[(position - shift) % 26]
    else:
        plain += letter

print("Estimated shift:", shift)
print("Decrypted message:", plain)