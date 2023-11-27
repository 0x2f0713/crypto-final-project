import random
import hashlib

FIXED_LENGTH = 128
def add_points(P, Q, p):
    x1, y1 = P
    x2, y2 = Q

    if x1 == x2 and y1 == y2:
        beta = (3*x1*x2 + a) * pow(2*y1, -1, p)
    else:
        beta = (y2 - y1) * pow(x2 - x1, -1, p)

    x3 = (beta*beta - x1 - x2) % p
    y3 = (beta * (x1 - x3) - y1) % p

    is_on_curve((x3, y3), p)

    return x3, y3

def is_on_curve(P, p):
    x, y = P
    assert (y*y) % p == ( pow(x, 3, p) + a*x + b ) % p
    return True

def apply_double_and_add_method(G, k, p):
    target_point = G

    k_binary = bin(k)[2:] #0b1111111001

    for i in range(1, len(k_binary)):
        current_bit = k_binary[i: i+1]

        # doubling - always
        target_point = add_points(target_point, target_point, p)

        if current_bit == "1":
            target_point = add_points(target_point, G, p)

    is_on_curve(target_point, p)

    return target_point
  
def legendre_symbol(a, p):
    return pow(a, (p - 1) // 2, p)

def sqrt_mod(a, p):
    if legendre_symbol(a, p) != 1:
        raise ValueError(f"{a} is not a quadratic residue modulo {p}")

    # Tonelli-Shanks algorithm for finding square roots modulo a prime
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1

    if s == 1:
        return pow(a, (p + 1) // 4, p)

    for z in range(2, p):
        if legendre_symbol(z, p) == -1:
            break

    c = pow(z, q, p)
    r = pow(a, (q + 1) // 2, p)
    t = pow(a, q, p)
    m = s

    while t != 1:
        i = 0
        temp = t
        while temp != 1:
            temp = (temp * temp) % p
            i += 1

        b = pow(c, 2 ** (m - i - 1), p)
        r = (r * b) % p
        t = (t * b * b) % p
        c = (b * b) % p
        m = i

    return r

def encode_message(message: str, a, b, q):
    k = len(bin(q)) - 2  # Bit length of the prime field
    l = k - 1 - FIXED_LENGTH  # Assume one bit is subtracted from the fixed-length message

    x = int(message, 2) << l
    # print(bin(x)[2:])
    for _ in range(2**l):  # Try 2^l times
        x_prime = (x**3 + a*x + b) % q  # Compute x'^3 + ax + b mod q

        if legendre_symbol(x_prime, q) == 1:  # Check if x' is a quadratic residue
            y_sqrt = sqrt_mod(x_prime, q)  # Compute square root of x' mod q
            return x, y_sqrt
        else:
            x += 1  # Increment the last l bits of x
            x_prime = (x**3 + a*x + b) % q  # Compute x'^3 + ax + b mod q
            if legendre_symbol(x_prime, q) == 1:  # Check if x' is a quadratic residue
                y_sqrt = sqrt_mod(x_prime, q)  # Compute square root of x' mod q
                return x, y_sqrt

    raise ValueError("non-encodable")

def decode_point(point, a, b, q):
    x, y = point
    padding_length = len(bin(q)) - 2 - 1 - FIXED_LENGTH

    # Ensure that the point is on the curve
    if (y**2 % q) != ((x**3 + a*x + b) % q):
        raise ValueError("Invalid point")

    # Extract the original message by removing trailing zeros
    binary_message = bin(x)[2:]
    print("Decoded part: ", binary_message)
    original_message = binary_message[:-padding_length]
    while (len(original_message) < FIXED_LENGTH):
        original_message = "0" + original_message
    return original_message

def textToInt(text):
 encoded_text = text.encode('utf-8')
 hex_text = encoded_text.hex()
 int_text = int(hex_text, 16)
 return int_text

# message = "Chào mừng 20 năm ngày thành lập trường ĐHCN"
# m = textToInt(message)
# hash_hex = hashlib.sha1(message.encode('utf-8')).hexdigest()
# hash_int = int(hash_hex, 16)
m = "Chào mừng 20 năm ngày thành lập trường ĐHCN"
# m = "Chao mung 20 nam ngay thanh lap truong DHCN"
binary_m = str(''.join(format(i, '08b') for i in bytearray(m, encoding ='utf-8')))
print("Origin message: ", m.encode('utf-8').hex())

# Secp256k1
a = 0; b = 7
G = (55066263022277343669578718895168534326250603453777594175500187360389116729240,
     32670510020758816978083085130507043184471273380659243275938904335757337482424)

p = pow(2, 256) - pow(2, 32) - pow(2, 9) - pow(2, 8) - pow(2, 7) - pow(2, 6) - pow(2, 4) - pow(2, 0)
n = 115792089237316195423570985008687907852837564279074904382605163141518161494337

# Alice: Generate private key and public key
# private key of Alice
alice_private_key = random.getrandbits(256)

# public key of Alice
alice_public__key = apply_double_and_add_method(G = G, k = alice_private_key, p = p)

# Bob: Generate private key and public key
bob_private_key = random.getrandbits(256)
bob_public__key = apply_double_and_add_method(G = G, k = bob_private_key, p = p)

# Alice: Encrpyt message
def encrypt(m, r):
    s = encode_message(m, a, b, p) 
    print("Encoded point: ", s)

    c1 = apply_double_and_add_method(G = G, k = r, p = p)

    c2 = apply_double_and_add_method(G = bob_public__key, k = r, p = p)
    c2 = add_points(c2, s, p)

    return c1, c2

# -------------------------
# r = random.getrandbits(128)
# c1, c2 = encrypt(m, r)

# # Sign
# r = ( bob_public__key[0] ) % n
# s = ( ( hash_int + r * alice_private_key ) * pow(bob_private_key, -1, n) ) % n



# Bob: Start decrypt
def decrypt(c1, c2):
    c1_prime = (c1[0], (-1*c1[1]) % p)
    s_prime = apply_double_and_add_method(G = c1_prime, k = bob_private_key, p = p)
    s_prime = add_points(P = c2, Q = s_prime, p = p)
    return s_prime

# s_prime = decrypt(c1, c2)

# # Bob: Start verification
# w = pow(s, -1, n)
# u1 = apply_double_and_add_method(G = G, k = ( hash_int * w ) % n, p = p)
# u2 = apply_double_and_add_method(G = alice_public__key, k = ( r * w ) % n, p = p)

# # u1 + u2
# checkpoint = add_points(P = u1, Q = u2, p = p)

# assert checkpoint[0] == r

binary_decrypted_message = ""
part_number = 1
for i in range(0, len(binary_m), FIXED_LENGTH):
    print("Processing part #", part_number)
    print("----------------------------")
    print("Alice action: ")
    print("-----")
    org_part = binary_m[i:i + FIXED_LENGTH]
    while (len(org_part) < FIXED_LENGTH): # Add padding if length smaller than FIXED_LENGTH
        org_part += "0"
    print("Origin msg (Bin): ", org_part)
    # Signing
    hash_hex = hashlib.sha512(org_part.encode("ascii")).hexdigest()
    hash_int = int(hash_hex, 16)
    r = (bob_public__key[0] ) % n
    s = ((hash_int + r * alice_private_key ) * pow(bob_private_key, -1, n) ) % n
    # Encrypt
    rand = random.getrandbits(128)
    c1, c2 = encrypt(org_part, rand)

    print("----------------------------")
    print("Bob action:")
    print("-----")
    # Decrypt
    decrypted = decrypt(c1, c2)
    print("Decrypted point:", decrypted)
    decoded = decode_point(decrypted, a, b, p)
    print("Decoded msg (Bin): ", decoded)
    decrypted_message = int(decoded, 2).to_bytes(FIXED_LENGTH // 8, byteorder='big')
    print("Decrypted part #", part_number, ": Plain text:", decrypted_message.decode("utf-8"))
    
    # Verification
    w = pow(s, -1, n)
    u1 = apply_double_and_add_method(G = G, k = ( hash_int * w ) % n, p = p)
    u2 = apply_double_and_add_method(G = alice_public__key, k = ( r * w ) % n, p = p)
    # u1 + u2
    checkpoint = add_points(P = u1, Q = u2, p = p)
    
    if (checkpoint[0] == r):
        print("Signature has been verified")
    print("----------------------------")
    binary_decrypted_message += decoded
    part_number += 1
    print()

decrypted_message = int(binary_decrypted_message, 2).to_bytes((len(binary_decrypted_message) + 7) // 8, byteorder='big')
print(decrypted_message.decode("utf-8"))