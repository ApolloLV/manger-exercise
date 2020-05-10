#!/usr/bin/python3

import math
import sys
from decimal import *
from subprocess import Popen, PIPE
from Crypto.Hash import SHA
from Crypto.Signature.PKCS1_PSS import MGF1
from Crypto.Util.number import size
from Crypto.Util.strxor import strxor


# Modified OAEP decoding function extracted from pycrypto
def oaep_unpad(k: int, plaintext: bytes) -> bytes:
	def bchr(s):
		return bytes([s])

	def bord(s):
		return s

	_hashObj = SHA  # Assume SHA1 was used
	hLen = _hashObj.digest_size
	_mgf = lambda x, y: MGF1(x, y, _hashObj)
	label = b""  # Assume empty label

	m = plaintext
	# Complete step 2c (I2OSP)
	em = bchr(0x00)*(k-len(m)) + m
	# Step 3a
	lHash = _hashObj.new(label).digest()
	# Step 3b
	y = em[0]
	# y must be 0, but we MUST NOT check it here in order not to
	# allow attacks like Manger's (http://dl.acm.org/citation.cfm?id=704143)
	maskedSeed = em[1:hLen+1]
	maskedDB = em[hLen+1:]
	# Step 3c
	seedMask = _mgf(maskedDB, hLen)
	# Step 3d
	seed = strxor(maskedSeed, seedMask)
	# Step 3e
	dbMask = _mgf(seed, k-hLen-1)
	# Step 3f
	db = strxor(maskedDB, dbMask)
	# Step 3g
	valid = 1
	one = db[hLen:].find(bchr(0x01))
	lHash1 = db[:hLen]
	if lHash1 != lHash:
		print("It appears they used a non-blank label.  This shouldn't matter...")
	if one < 0:
		valid = 0
	if bord(y) != 0:
		valid = 0
	if not valid:
		raise ValueError("Incorrect decryption.")
	# Step 4
	return db[hLen+one+1:]


# Helper function that tries f with the oracle and returns the oracle response error message
def send_to_oracle(f: int) -> str:
	def modulus_power(base: int, exponent: int, modulus: int) -> int:
		result = 1
		while exponent > 0:
			if exponent & 1 == 1:
				result = (result * base) % modulus
			exponent = exponent >> 1
			base = (base * base) % modulus
		return result

	f_encrypted = modulus_power(f, e, n)
	f_c_encrypted = (f_encrypted * c) % n
	f_c_encrypted_hex = hex(f_c_encrypted)[2:]

	# Send the hex string to libgcrypt and try decrypting
	decrypt_pipe = Popen(["./decrypt", f_c_encrypted_hex], stdout=PIPE)
	# Get the first line of the response
	libgcrypt_response = decrypt_pipe.communicate()[0].decode()
	decrypt_pipe.terminate()
	return libgcrypt_response


def greater_than_B(libgcrypt_response):
	# TODO: Implement oracle
	# Integer to Octets Failure (e.g. frame[0] or Invalid Obj) indicates y >= B
	return 'Missing item in object' in libgcrypt_response


def step_1():
	# TODO: Implement step 1
	f1 = 2
	while not greater_than_B(send_to_oracle(f1)):
		f1 = 2 * f1
	return f1


def step_2(f1):
	# TODO: Implement step 2
	f2 = int(math.floor((n + B) / B) * (f1 / 2))
	while greater_than_B(send_to_oracle(f2)):
		f2 = f2 + int(f1 / 2)
	return f2


def step_3(f2):
	# TODO: BONUS Implement step 3
	m_min = Decimal(n / f2).to_integral_value(rounding=ROUND_CEILING)
	m_max = Decimal((n + B) / f2).to_integral_value(rounding=ROUND_FLOOR)

	while m_min < m_max:
		f_tmp = Decimal((2 * B) / (m_max - m_min)).to_integral_value(rounding=ROUND_FLOOR)
		i = Decimal(f_tmp * m_min / n).to_integral_value(rounding=ROUND_CEILING)
		f3 = int(Decimal((i * n) / m_min).to_integral_value(rounding=ROUND_CEILING))

		difference = float(m_max - m_min)
		print(f"Interval width: {difference}")

		if greater_than_B(send_to_oracle(f3)):
			m_min = Decimal((i * n + B) / f3).to_integral_value(rounding=ROUND_CEILING)
		else:
			m_max = Decimal((i * n + B) / f3).to_integral_value(rounding=ROUND_FLOOR)
	return m_min


def mangers_oracle():
	# Increase precision of Decimal class
	getcontext().prec=350

	# Try if the oracle works reliably
	# TODO: Implement the greater_than_B function
	assert greater_than_B(send_to_oracle(2)) is False, "greater_than_B should return False for an input of 2"
	assert greater_than_B(send_to_oracle(256)) is True, "greater_than_B should return True for an input of 256"

	# Run the three steps
	f1 = step_1()
	print(f"Finished Step 1 with a f1 of {f1}")
	f2 = step_2(f1)
	print(f"Finished Step 2 with a f2 of {f2}")
	m = step_3(f2)
	print(f"Finished Step 3")
	print(f"Plaintext message m = {m.to_integral_value()}")

	# Process the recovered plaintext
	plaintext_bytes = int(m.to_integral_value()).to_bytes(length=k, byteorder='big')
	unpadded_plaintext = oaep_unpad(k, plaintext_bytes)
	print("The unpadded plaintext, in hexadecimal:")
	print(f"0x{bytearray(unpadded_plaintext).hex()}")


# Public key n
n = 157864837766412470414898605682479126709913814457720048403886101369805832566211909035448137352055018381169566146003377316475222611235116218157405481257064897859932106980034542393008803178451117972197473517842606346821132572405276305083616404614783032204836434549683833460267309649602683257403191134393810723409
# Public key e
e = 0x10001
# Intercepted ciphertext c
c = int('5033692c41c8a1bdc2c78eadffc47da73470b2d25c9dc0ce2c0d0282f0d5f845163ab6f2f296540c1a1090d826648e12644945ab922a125bb9c67f8caaef6b4abe06b92d3365075fbb5d8f19574ddb5ee80c0166303702bbba249851836a58c3baf23f895f9a16e5b15f2a698be1e3efb74d5c5c4fddc188835a16cf7c9c132c', 16)
# Public key size k
k = int(Decimal(str(math.log(n, 256))).to_integral_value(rounding=ROUND_CEILING))
# Manger's B to compare to
B = getcontext().power(Decimal(2), Decimal(8*(k-1)))

# Run the oracle with this key and ciphertext
mangers_oracle()
