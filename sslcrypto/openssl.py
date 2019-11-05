import ctypes
import os

lib = None


def init():
	global aes, ecies, rsa

	# Initialize functions
	lib.SSLeay_version.restype = ctypes.c_char_p

	# Initialize internal state
	lib.OPENSSL_add_all_algorithms_conf()

	aes = AES()
	ecies = ECIES()
	rsa = RSA()


class AES:
	ALGOS = (
		"aes-128-cbc", "aes-192-cbc", "aes-256-cbc",
		"aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
		"aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
		"aes-128-ofb", "aes-192-ofb", "aes-256-ofb"
	)

	def __init__(self):
		# 1 KiB ought to be enough for everybody. We don't know the real size of
		# the context buffer because we are unsure about padding and pointer
		# size
		self.ctx = ctypes.create_string_buffer(1024)


	def _get_cipher(self, algo):
		if algo not in self.ALGOS:
			raise ValueError("Unknown cipher algorithm {}".format(algo))
		cipher = lib.EVP_get_cipherbyname(algo.encode())
		if not cipher:
			raise ValueError("Unknown cipher algorithm {}".format(algo))
		return cipher


	def encrypt(self, data, key, algo="aes-256-cbc"):
		# Initialize context
		lib.EVP_CIPHER_CTX_init(self.ctx)
		try:
			lib.EVP_CipherInit_ex(self.ctx, self._get_cipher(algo), None, None, None)

			# Make sure key length is correct
			key_length = lib.EVP_CIPHER_CTX_key_length(self.ctx)
			if len(key) != key_length:
				raise ValueError("Expected key to be {} bytes, got {} bytes".format(key_length, len(key)))

			# Generate random IV
			iv_length = lib.EVP_CIPHER_CTX_iv_length(self.ctx)
			iv = os.urandom(iv_length)

			# Set key and IV
			lib.EVP_CipherInit_ex(self.ctx, None, None, key, iv)

			# Actually encrypt
			block_size = lib.EVP_CIPHER_CTX_block_size(self.ctx)
			output = ctypes.create_string_buffer((len(data) // block_size + 1) * block_size)
			output_len = ctypes.c_int()

			if not lib.EVP_CipherUpdate(self.ctx, output, ctypes.byref(output_len), data, len(data)):
				raise ValueError("Could not feed cipher with data")

			new_output = ctypes.byref(output, output_len.value)
			output_len2 = ctypes.c_int()
			if not lib.EVP_CipherFinal_ex(self.ctx, new_output, ctypes.byref(output_len2)):
				raise ValueError("Could not finalize cipher")

			ciphertext = output[:output_len.value + output_len2.value]
			return ciphertext, iv
		finally:
			lib.EVP_CIPHER_CTX_cleanup(self.ctx)


	def decrypt(self, ciphertext, iv, key, algo="aes-256-cbc"):
		# Initialize context
		lib.EVP_CIPHER_CTX_init(self.ctx)
		try:
			lib.EVP_DecryptInit_ex(self.ctx, self._get_cipher(algo), None, None, None)

			# Make sure key length is correct
			key_length = lib.EVP_CIPHER_CTX_key_length(self.ctx)
			if len(key) != key_length:
				raise ValueError("Expected key to be {} bytes, got {} bytes".format(key_length, len(key)))

			# Make sure IV length is correct
			iv_length = lib.EVP_CIPHER_CTX_iv_length(self.ctx)
			if len(iv) != iv_length:
				raise ValueError("Expected IV to be {} bytes, got {} bytes".format(iv_length, len(iv)))

			# Make sure ciphertext length is correct
			block_size = lib.EVP_CIPHER_CTX_block_size(self.ctx)
			if len(ciphertext) % block_size != 0:
				raise ValueError("Expected ciphertext to be a multiple of {} bytes, got {} bytes".format(block_size, len(ciphertext)))

			# Set key and IV
			lib.EVP_DecryptInit_ex(self.ctx, None, None, key, iv)

			# Actually decrypt
			output = ctypes.create_string_buffer(len(ciphertext))
			output_len = ctypes.c_int()

			if not lib.EVP_DecryptUpdate(self.ctx, output, ctypes.byref(output_len), ciphertext, len(ciphertext)):
				raise ValueError("Could not feed decipher with ciphertext")

			new_output = ctypes.byref(output, output_len.value)
			output_len2 = ctypes.c_int()
			if not lib.EVP_DecryptFinal_ex(self.ctx, new_output, ctypes.byref(output_len2)):
				raise ValueError("Could not finalize decipher")

			return output[:output_len.value + output_len2.value]
		finally:
			lib.EVP_CIPHER_CTX_cleanup(self.ctx)



class ECIES:
	pass



class RSA:
	pass
