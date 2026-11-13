# Simulating an error and correcting it

codeword = [0, 1, 1, 0, 0, 1, 1]

# Introduce an error at position 6
codeword[5] = 1 - codeword[5]

# Calculate syndrome bits
C1 = codeword[0] ^ codeword[2] ^ codeword[4] ^ codeword[6]
C2 = codeword[1] ^ codeword[2] ^ codeword[5] ^ codeword[6]
C4 = codeword[3] ^ codeword[4] ^ codeword[5] ^ codeword[6]

syndrome = C4 * 4 + C2 * 2 + C1

print("Received codeword:", ''.join(map(str, codeword)))
print("Syndrome:", format(syndrome, '03b'))

# Correct the error
if syndrome != 0:
    codeword[syndrome - 1] = 1 - codeword[syndrome - 1]

print("Corrected codeword:", ''.join(map(str, codeword)))
