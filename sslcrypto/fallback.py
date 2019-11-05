import pyaes
import ecdsa
import os
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
            self.public_key_length = len(bin(n).replace("0b", "")) // 8


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



class RSA:
    pass


aes = AES()
ecc = ECC(ECCBackend())
rsa = RSA()
