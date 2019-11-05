import hashlib
import pyaes
import ecdsa
import time
import os
from . import _jacobian as jacobian
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
            0,
            7,
            0x79BE667E_F9DCBBAC_55A06295_CE870B07_029BFCDB_2DCE28D9_59F2815B_16F81798,
            0x483ADA77_26A3C465_5DA4FBFC_0E1108A8_FD17B448_A6855419_9C47D08F_FB10D4B8,
            0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141
        )
    }

    def is_supported(self, name):
        return name in self.CURVES

    class EllipticCurveBackend:
        def __init__(self, name):
            # Create curve object
            p, a, b, gx, gy, n = ECCBackend.CURVES[name]
            field = ecdsa.ellipticcurve.CurveFp(p, a, b)
            self.curve = ecdsa.curves.Curve(
                name,
                field,
                ecdsa.ellipticcurve.Point(field, gx, gy, n),
                (0, 0),  # oid should be here, but it's not required
                name
            )
            self.public_key_length = (len(bin(n).replace("0b", "")) + 7) // 8


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


        def decompress_point(self, public_key):
            # Parse & load data
            p, a, b = self.curve.curve.p(), self.curve.curve.a(), self.curve.curve.b()
            x = self._bytes_to_int(public_key[1:])
            # Calculate Y
            y_square = (pow(x, 3, p) + a * x + b) % p
            try:
                y = ecdsa.numbertheory.square_root_mod_prime(y_square, p)
            except Exception:
                raise ValueError("Invalid public key") from None
            if y % 2 != public_key[0] - 0x02:
                y = p - y
            # Ensure the point is correct
            if not ecdsa.ecdsa.point_is_valid(self.curve.generator, x, y):
                raise ValueError("Public key does not lay on the curve")
            return self._int_to_bytes(x), self._int_to_bytes(y)


        def new_private_key(self):
            raw = ecdsa.SigningKey.generate(curve=self.curve).privkey.secret_multiplier
            return self._int_to_bytes(raw)


        def private_to_public(self, private_key):
            raw = self._bytes_to_int(private_key)
            sk = ecdsa.SigningKey.from_secret_exponent(raw, curve=self.curve)
            point = sk.verifying_key.pubkey.point
            x, y = point.x(), point.y()
            return self._int_to_bytes(x), self._int_to_bytes(y)


        def ecdh(self, private_key, public_key):
            x, y = public_key
            x, y = self._bytes_to_int(x), self._bytes_to_int(y)
            private_key = self._bytes_to_int(private_key)
            point = ecdsa.ellipticcurve.Point(self.curve.curve, x, y, order=self.curve.order)
            return self._int_to_bytes((point * private_key).x())


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

            raw_private_key = self._bytes_to_int(private_key)
            sk = ecdsa.SigningKey.from_secret_exponent(raw_private_key, curve=self.curve)

            g = sk.privkey.public_key.generator
            order = g.order()

            # Generate k deterministically from data
            h = hashlib.sha512()
            h.update(data)
            h.update(b"\x00")
            h.update(str(time.time()).encode())
            k = self._bytes_to_int(h.digest()) % order

            while True:
                # Fix k length to prevent Minerva. Increasing multiplier by a
                # multiple of order doesn't break anything. This fix was ported
                # from python-ecdsa
                ks = k + order
                kt = ks + order
                ks_len = len(bin(ks).replace("0b", "")) // 8
                kt_len = len(bin(kt).replace("0b", "")) // 8
                if ks_len == kt_len:
                    p1 = kt * g
                else:
                    p1 = ks * g
                r = p1.x() % order
                if r == 0:
                    # Invalid k, try increasing it
                    k = (k + 1) % order
                    continue

                s = (ecdsa.numbertheory.inverse_mod(k, order) * (z + (sk.privkey.secret_multiplier * r))) % order
                if s == 0:
                    # Invalid k, try increasing it
                    k = (k + 1) % order
                    continue

                recid = (p1.y() % 2) ^ (s * 2 >= order)
                recid += 2 * int(p1.x() // order)

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

            recid = signature[0] - 31
            r = self._bytes_to_int(signature[1:self.public_key_length + 1])
            s = self._bytes_to_int(signature[self.public_key_length + 1:])

            # Verify bounds
            if not (0 <= recid < 2 * (self.curve.curve.p() // self.curve.order + 1)):
                raise ValueError("Invalid recovery ID")
            if r >= self.curve.order:
                raise ValueError("r is out of bounds")
            if s >= self.curve.order:
                raise ValueError("s is out of bounds")

            z = self._bytes_to_int(subject[:self.curve.baselen])
            rinv = ecdsa.numbertheory.inverse_mod(r, self.curve.order)
            u1 = (-z * rinv) % self.curve.order
            u2 = (s * rinv) % self.curve.order

            # Recover R
            rx = r + (recid // 2) * self.curve.order
            if rx >= self.curve.order:
                raise ValueError("Rx is out of bounds")
            ry_mod = (recid % 2) ^ (s * 2 >= self.curve.order)

            # Almost copied from decompress_point
            p, a, b = self.curve.curve.p(), self.curve.curve.a(), self.curve.curve.b()
            ry_square = (pow(rx, 3, p) + a * rx + b) % p
            try:
                ry = ecdsa.numbertheory.square_root_mod_prime(ry_square, p)
            except Exception:
                raise ValueError("Invalid recovered public key") from None
            # Ensure the point is correct
            if ry % 2 != ry_mod:
                # Fix Ry sign
                ry = p - ry
            rp = ecdsa.ellipticcurve.Point(self.curve.curve, rx, ry, self.curve.order)

            # Convert to Jacobian for performance
            jacobian.change_curve(
                self.curve.curve.p(),
                self.curve.order,
                self.curve.curve.a(),
                self.curve.curve.b(),
                self.curve.generator.x(),
                self.curve.generator.y()
            )
            x, y = jacobian.fast_add(
                jacobian.fast_multiply(jacobian.G, u1),
                jacobian.fast_multiply((rp.x(), rp.y()), u2)
            )
            return self._int_to_bytes(x), self._int_to_bytes(y)


class RSA:
    pass


aes = AES()
ecc = ECC(ECCBackend())
rsa = RSA()
