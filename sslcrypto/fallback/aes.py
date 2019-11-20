import os
import pyaes


__all__ = ["aes"]

class AES:
    def _parse_algo_name(self, algo):
        if not algo.startswith("aes-") or algo.count("-") != 2:
            raise ValueError("Unknown cipher algorithm {}".format(algo))
        key_length, cipher_type = algo[4:].split("-")
        if key_length not in ("128", "192", "256"):
            raise ValueError("Unknown cipher algorithm {}".format(algo))
        if cipher_type not in ("cbc", "ctr", "cfb", "ofb"):
            raise ValueError("Unknown cipher algorithm {}".format(algo))
        return int(key_length) // 8, cipher_type


    def get_algo_key_length(self, algo):
        return self._parse_algo_name(algo)[0]


    def new_key(self, algo="aes-256-cbc"):
        key_length, _ = self._parse_algo_name(algo)
        return os.urandom(key_length)


    def encrypt(self, data, key, algo="aes-256-cbc"):
        key_length, cipher_type = self._parse_algo_name(algo)
        if len(key) != key_length:
            raise ValueError("Expected key to be {} bytes, got {} bytes".format(key_length, len(key)))

        # Generate random IV
        iv = os.urandom(16)

        if cipher_type == "cbc":
            cipher = pyaes.AESModeOfOperationCBC(key, iv=iv)
        elif cipher_type == "ctr":
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
        elif cipher_type == "cfb":
            # Change segment size from default 8 bytes to 16 bytes for OpenSSL
            # compatibility
            cipher = pyaes.AESModeOfOperationCFB(key, iv, segment_size=16)
        elif cipher_type == "ofb":
            cipher = pyaes.AESModeOfOperationOFB(key, iv)

        encrypter = pyaes.Encrypter(cipher)
        ciphertext = encrypter.feed(data)
        ciphertext += encrypter.feed()
        return ciphertext, iv


    def decrypt(self, ciphertext, iv, key, algo="aes-256-cbc"):
        key_length, cipher_type = self._parse_algo_name(algo)
        if len(key) != key_length:
            raise ValueError("Expected key to be {} bytes, got {} bytes".format(key_length, len(key)))

        if cipher_type == "cbc":
            cipher = pyaes.AESModeOfOperationCBC(key, iv=iv)
        elif cipher_type == "ctr":
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
        elif cipher_type == "cfb":
            # Change segment size from default 8 bytes to 16 bytes for OpenSSL
            # compatibility
            cipher = pyaes.AESModeOfOperationCFB(key, iv, segment_size=16)
        elif cipher_type == "ofb":
            cipher = pyaes.AESModeOfOperationOFB(key, iv)

        decrypter = pyaes.Decrypter(cipher)
        data = decrypter.feed(ciphertext)
        data += decrypter.feed()
        return data


    def get_backend(self):
        return "fallback"


aes = AES()
