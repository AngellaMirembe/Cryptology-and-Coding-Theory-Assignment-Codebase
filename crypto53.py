# (7,4) Cyclic Code Encoder

def modulo2_division(dividend, divisor):
    dividend = list(map(int, dividend))
    divisor = list(map(int, divisor))

    for i in range(len(dividend) - len(divisor) + 1):
        if dividend[i] == 1:
            for j in range(len(divisor)):
                dividend[i + j] ^= divisor[j]

    remainder = dividend[-(len(divisor) - 1):]
    return ''.join(map(str, remainder))


message = "1101"
generator = "1011"

# Append three zeros
dividend = message + "000"

# Calculate remainder
remainder = modulo2_division(dividend, generator)

# Generate codeword
codeword = message + remainder

print("Original message:", message)
print("Generator polynomial:", generator)
print("Remainder:", remainder)
print("Encoded codeword:", codeword)

# Verify the codeword
verification = modulo2_division(codeword, generator)

print("Verification remainder:", verification)