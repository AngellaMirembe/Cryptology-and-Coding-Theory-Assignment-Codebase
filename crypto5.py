# Hamming (7,4) Encoder

data = "1011"

code = [0] * 8

# Place data bits
code[3] = int(data[0])
code[5] = int(data[1])
code[6] = int(data[2])
code[7] = int(data[3])

# Calculate parity bits using even parity
code[1] = code[3] ^ code[5] ^ code[7]
code[2] = code[3] ^ code[6] ^ code[7]
code[4] = code[5] ^ code[6] ^ code[7]

# Display transmitted codeword
codeword = ''.join(str(code[i]) for i in range(1, 8))

print("Original data:", data)
print("Transmitted codeword:", codeword)