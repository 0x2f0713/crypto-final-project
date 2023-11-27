import time
import random
import math

# import cryptocommons as commons

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


starttime = time.time()

"""p = 999900048617
q = 999900049387"""

from Crypto.PublicKey import RSA
RSAkey = RSA.generate(3072)
p = getattr(RSAkey, 'p')
q = getattr(RSAkey, 'q')

n = p*q
totient = (p-1)*(q-1)

print("mod: ",n)
print("totient function",totient)

e = random.randint(1, totient)

#e and totient must be coprime

while math.gcd(totient, e) != 1:
	e = random.randint(1, totient)

print("public key: ",e)

#-------------------------------
#find multiplicative inverse of e mod totient

#brute force
"""d=0
for i in range(totient):
	if (e*i) % totient == 1:
		d = i
		break
"""

# d = commons.modInverse(e, totient)
d = pow(e, -1, totient)

print("private key: ",d)

print("key generation is complete in ",time.time() - starttime," seconds\n")

publickey = e 
privatekey = d

#--------------------------------

print("-------------------------")
print("message encryption")
print("-------------------------")

m = 11

ciphertext = pow(m, e, n)
print("ciphertext: ",ciphertext)
print("encryption is complete in ",time.time() - starttime," seconds\n")

restored = pow(ciphertext, d, n)
print("restored: ", restored)
print("decryption is complete in ",time.time() - starttime," seconds")

#--------------------------------

print("-------------------------")
print("digital signature")
print("-------------------------")

import hashlib

print("Alice:")

message = b'hello, world!'

hashHex = hashlib.sha256(message).hexdigest()
hash = int(hashHex, 16)

print("message", message)
print("hash: ",hash)

signature = pow(hash, privatekey, n)
print("signature: ",signature)

#alice sends bob message, signature
#--------------------------------

print("Bob:")

decryptedSignature = pow(signature, publickey, n)
print("decryptedSignature: ",decryptedSignature)

bobHashHex = hashlib.sha256(message).hexdigest()
bobHash = int(bobHashHex, 16)
print("Bob calculates this hash value: ",bobHash)

if bobHash == decryptedSignature:
	print("signature is valid")
else:
	print("signature is not valid!!!")

#--------------------------------
print("-------------------------")
print("key exchange")
print("-------------------------")

print("Bob:")

key = 1234567891234567 #16 byte
encryptedkey = pow(key, publickey, n)
print("encryptedkey: ",encryptedkey)

message = "hi alice, howdy?"

from Crypto.Cipher import AES

obj = AES.new(str(key))
ciphertext = obj.encrypt(message)

print("ciphertext: ", ciphertext)

#now, bob sends ciphertext and encrypted key to Alice
#--------------------------------
print("Alice:")

restoredkey = pow(encryptedkey, privatekey, n)
print("restored key: ",restoredkey)

obj2 = AES.new(str(restoredkey))
restoredtext = obj2.decrypt(ciphertext)

print("restoredtext: ",restoredtext)