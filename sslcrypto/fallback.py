import hashlib
import pyaes
import time
import os
from ._jacobian import JacobianCurve
from ._ecc import ECC

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


class ECCBackend:
    CURVES = {
        "secp256k1": (
            0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFC2F,
            0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141,
            0,
            7,
            (
                0x79BE667E_F9DCBBAC_55A06295_CE870B07_029BFCDB_2DCE28D9_59F2815B_16F81798,
                0x483ADA77_26A3C465_5DA4FBFC_0E1108A8_FD17B448_A6855419_9C47D08F_FB10D4B8
            )
        )
    }

    def is_supported(self, name):
        return name in self.CURVES

    class EllipticCurveBackend:
        def __init__(self, name):
            self.aes = aes

            self.p, self.n, self.a, self.b, self.g = ECCBackend.CURVES[name]
            self.jacobian = JacobianCurve(*ECCBackend.CURVES[name])

            self.public_key_length = (len(bin(self.n).replace("0b", "")) + 7) // 8


        def _int_to_bytes(self, raw):
            data = []
            for _ in range(self.public_key_length):
                data.append(raw % 256)
                raw //= 256
            return bytes(data[::-1])


        def _bytes_to_int(self, data):
            raw = 0
            for byte in data:
                raw = raw * 256 + byte
            return raw


        def _legendre(self, a, p):
            res = pow(a, (p - 1) // 2, p)
            if res == p - 1:
                return -1
            else:
                return res


        def _square_root_mod_prime(self, n, p):
            if n == 0:
                return 0
            if p == 2:
                return n  # We should never get here but it might be useful
            if self._legendre(n, p) != 1:
                raise ValueError("No square root")
            # Optimizations
            if p % 4 == 3:
                return pow(n, (p + 1) // 4, p)
            # 1. By factoring out powers of 2, find Q and S such that p - 1 =
            # Q * 2 ** S with Q odd
            q = p - 1
            s = 0
            while q % 2 == 0:
                q //= 2
                s += 1
            # 2. Search for z in Z/pZ which is a quadratic non-residue
            z = 1
            while self._legendre(z, p) != -1:
                z += 1
            m, c, t, r = s, pow(z, q, p), pow(n, q, p), pow(n, (q + 1) // 2, p)
            while True:
                if t == 0:
                    return 0
                elif t == 1:
                    return r
                # Use repeated squaring to find the least i, 0 < i < M, such
                # that t ** (2 ** i) = 1
                t_sq = t
                i = 0
                for i in range(1, m):
                    t_sq = t_sq * t_sq % p
                    if t_sq == 1:
                        break
                else:
                    raise ValueError("Should never get here")
                # Let b = c ** (2 ** (m - i - 1))
                b = pow(c, 2 ** (m - i - 1), p)
                m = i
                c = b * b % p
                t = t * b * b % p
                r = r * b % p
            return r



        def decompress_point(self, public_key):
            # Parse & load data
            x = self._bytes_to_int(public_key[1:])
            # Calculate Y
            y_square = (pow(x, 3, self.p) + self.a * x + self.b) % self.p
            try:
                y = self._square_root_mod_prime(y_square, self.p)
            except Exception:
                raise ValueError("Invalid public key") from None
            if y % 2 != public_key[0] - 0x02:
                y = self.p - y
            return self._int_to_bytes(x), self._int_to_bytes(y)


        def new_private_key(self):
            while True:
                private_key = os.urandom(self.public_key_length)
                if self._bytes_to_int(private_key) >= self.n:
                    continue
                return private_key


        def private_to_public(self, private_key):
            raw = self._bytes_to_int(private_key)
            x, y = self.jacobian.fast_multiply(self.g, raw)
            return self._int_to_bytes(x), self._int_to_bytes(y)


        def ecdh(self, private_key, public_key):
            x, y = public_key
            x, y = self._bytes_to_int(x), self._bytes_to_int(y)
            private_key = self._bytes_to_int(private_key)
            x, _ = self.jacobian.fast_multiply((x, y), private_key)
            return self._int_to_bytes(x)


        def sign(self, data, private_key, hash, recoverable):
            if callable(hash):
                subject = hash(data)
            elif hash == "sha256":
                h = hashlib.sha256()
                h.update(data)
                subject = h.digest()
            elif hash == "sha512":
                h = hashlib.sha512()
                h.update(data)
                subject = h.digest()
            elif hash is None:
                # *Highly* unrecommended. Only use this if the input is very
                # small
                subject = data
            else:
                raise ValueError("Unsupported hash function")

            z = self._bytes_to_int(subject[:self.public_key_length])
            private_key = self._bytes_to_int(private_key)

            # Generate k deterministically from data
            h = hashlib.sha512()
            h.update(data)
            h.update(b"\x00")
            h.update(str(time.time()).encode())
            k = self._bytes_to_int(h.digest()) % self.n

            while True:
                # Fix k length to prevent Minerva. Increasing multiplier by a
                # multiple of order doesn't break anything. This fix was ported
                # from python-ecdsa
                ks = k + self.n
                kt = ks + self.n
                ks_len = len(bin(ks).replace("0b", "")) // 8
                kt_len = len(bin(kt).replace("0b", "")) // 8
                if ks_len == kt_len:
                    k = kt
                else:
                    k = ks
                px, py = self.jacobian.fast_multiply(self.g, k)

                r = px % self.n
                if r == 0:
                    # Invalid k, try increasing it
                    k = (k + 1) % self.n
                    continue

                s = (self.jacobian.inv(k, self.n) * (z + (private_key * r))) % self.n
                if s == 0:
                    # Invalid k, try increasing it
                    k = (k + 1) % self.n
                    continue

                recid = (py % 2) ^ (s * 2 >= self.n)
                recid += 2 * int(px // self.n)

                return bytes([31 + recid]) + self._int_to_bytes(r) + self._int_to_bytes(s)


        def recover(self, signature, data, hash):
            if callable(hash):
                subject = hash(data)
            elif hash == "sha256":
                h = hashlib.sha256()
                h.update(data)
                subject = h.digest()
            elif hash == "sha512":
                h = hashlib.sha512()
                h.update(data)
                subject = h.digest()
            elif hash is None:
                # *Highly* unrecommended. Only use this if the input is very
                # small
                subject = data
            else:
                raise ValueError("Unsupported hash function")

            recid = signature[0] - 27 if signature[0] < 31 else signature[0] - 31
            r = self._bytes_to_int(signature[1:self.public_key_length + 1])
            s = self._bytes_to_int(signature[self.public_key_length + 1:])

            # Verify bounds
            if not (0 <= recid < 2 * (self.p // self.n + 1)):
                raise ValueError("Invalid recovery ID")
            if r >= self.n:
                raise ValueError("r is out of bounds")
            if s >= self.n:
                raise ValueError("s is out of bounds")

            z = self._bytes_to_int(subject[:self.public_key_length])
            rinv = self.jacobian.inv(r, self.n)
            u1 = (-z * rinv) % self.n
            u2 = (s * rinv) % self.n

            # Recover R
            rx = r + (recid // 2) * self.n
            if rx >= self.n:
                raise ValueError("Rx is out of bounds")
            ry_mod = (recid % 2) ^ (s * 2 >= self.n)

            # Almost copied from decompress_point
            ry_square = (pow(rx, 3, self.p) + self.a * rx + self.b) % self.p
            try:
                ry = self._square_root_mod_prime(ry_square, self.p)
            except Exception:
                raise ValueError("Invalid recovered public key") from None
            # Ensure the point is correct
            if ry % 2 != ry_mod:
                # Fix Ry sign
                ry = self.p - ry

            x, y = self.jacobian.fast_add(
                self.jacobian.fast_multiply(self.g, u1),
                self.jacobian.fast_multiply((rx, ry), u2)
            )
            return self._int_to_bytes(x), self._int_to_bytes(y)


class RSA:
    pass


aes = AES()
ecc = ECC(ECCBackend())
rsa = RSA()
