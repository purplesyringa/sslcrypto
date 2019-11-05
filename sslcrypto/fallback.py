import pyaes
import os

__all__ = ["aes", "ecies", "rsa"]


class AES:
	def _parseAlgoName(self, algo):
		if not algo.startswith("aes-") or algo.count("-") != 2:
			raise ValueError("Unknown cipher algorithm {}".format(algo))
		key_length, type = algo[4:].split("-")
		if key_length not in ("128", "192", "256"):
			raise ValueError("Unknown cipher algorithm {}".format(algo))
		if type not in ("cbc", "ctr", "cfb", "ofb"):
			raise ValueError("Unknown cipher algorithm {}".format(algo))
		return int(key_length) // 8, type


	def encrypt(self, data, key, algo="aes-256-cbc"):
		key_length, type = self._parseAlgoName(algo)
		if len(key) != key_length:
			raise ValueError("Expected key to be {} bytes, got {} bytes".format(key_length, len(key)))

		# Generate random IV
		iv = os.urandom(16)

		if type == "cbc":
			cipher = pyaes.AESModeOfOperationCBC(key, iv=iv)
		elif type == "ctr":
			# The IV is actually a counter, not an IV but it does almost the
			# same. Notice: pyaes always uses 1 as initial counter! Make sure
			# not to call pyaes directly.

			# We kinda do two conversions here: from byte array to int here, and
			# from int to byte array in pyaes internals. It's possible to fix that
			# but I didn't notice any performance changes so I'm keeping clean code.
			iv_int = 0
			for byte in iv:
				iv_int = (iv_int * 256) + byte
			counter = pyaes.Counter(iv_int)
			cipher = pyaes.AESModeOfOperationCTR(key, counter=counter)
		elif type == "cfb":
			# Change segment size from default 8 bytes to 16 bytes for OpenSSL
			# compatibility
			cipher = pyaes.AESModeOfOperationCFB(key, iv, segment_size=16)
		elif type == "ofb":
			cipher = pyaes.AESModeOfOperationOFB(key, iv)

		encrypter = pyaes.Encrypter(cipher)
		ciphertext = encrypter.feed(data)
		ciphertext += encrypter.feed()
		return ciphertext, iv


	def decrypt(self, ciphertext, iv, key, algo="aes-256-cbc"):
		key_length, type = self._parseAlgoName(algo)
		if len(key) != key_length:
			raise ValueError("Expected key to be {} bytes, got {} bytes".format(key_length, len(key)))

		if type == "cbc":
			cipher = pyaes.AESModeOfOperationCBC(key, iv=iv)
		elif type == "ctr":
			# The IV is actually a counter, not an IV but it does almost the
			# same. Notice: pyaes always uses 1 as initial counter! Make sure
			# not to call pyaes directly.

			# We kinda do two conversions here: from byte array to int here, and
			# from int to byte array in pyaes internals. It's possible to fix that
			# but I didn't notice any performance changes so I'm keeping clean code.
			iv_int = 0
			for byte in iv:
				iv_int = (iv_int * 256) + byte
			counter = pyaes.Counter(iv_int)
			cipher = pyaes.AESModeOfOperationCTR(key, counter=counter)
		elif type == "cfb":
			# Change segment size from default 8 bytes to 16 bytes for OpenSSL
			# compatibility
			cipher = pyaes.AESModeOfOperationCFB(key, iv, segment_size=16)
		elif type == "ofb":
			cipher = pyaes.AESModeOfOperationOFB(key, iv)

		decrypter = pyaes.Decrypter(cipher)
		data = decrypter.feed(ciphertext)
		data += decrypter.feed()
		return data


class ECIES:
	pass


class RSA:
	pass


aes = AES()
ecies = ECIES()
rsa = RSA()
