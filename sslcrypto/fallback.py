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


    def new_key(self, algo="aes-256-cbc"):
        key_length, _ = self._parseAlgoName(algo)
        return os.urandom(key_length)


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
        # "curvename": (p, n, a, b, (Gx, Gy)),
        "secp112r1": (
            0xDB7C_2ABF62E3_5E668076_BEAD208B,
            0xDB7C_2ABF62E3_5E7628DF_AC6561C5,
            0xDB7C_2ABF62E3_5E668076_BEAD2088,
            0x659E_F8BA0439_16EEDE89_11702B22,
            (
                0x0948_7239995A_5EE76B55_F9C2F098,
                0xA89C_E5AF8724_C0A23E0E_0FF77500
            )
        ),
        "secp112r2": (
            0xDB7C_2ABF62E3_5E668076_BEAD208B,
            0x36DF_0AAFD8B8_D7597CA1_0520D04B,
            0x6127_C24C05F3_8A0AAAF6_5C0EF02C,
            0x51DE_F1815DB5_ED74FCC3_4C85D709,
            (
                0x4BA3_0AB5E892_B4E1649D_D0928643,
                0xADCD_46F5882E_3747DEF3_6E956E97
            )
        ),
        "secp128r1": (
            0xFFFFFFFD_FFFFFFFF_FFFFFFFF_FFFFFFFF,
            0xFFFFFFFE_00000000_75A30D1B_9038A115,
            0xFFFFFFFD_FFFFFFFF_FFFFFFFF_FFFFFFFC,
            0xE87579C1_1079F43D_D824993C_2CEE5ED3,
            (
                0x161FF752_8B899B2D_0C28607C_A52C5B86,
                0xCF5AC839_5BAFEB13_C02DA292_DDED7A83
            )
        ),
        "secp128r2": (
            0xFFFFFFFD_FFFFFFFF_FFFFFFFF_FFFFFFFF,
            0x3FFFFFFF_7FFFFFFF_BE002472_0613B5A3,
            0xD6031998_D1B3BBFE_BF59CC9B_BFF9AEE1,
            0x5EEEFCA3_80D02919_DC2C6558_BB6D8A5D,
            (
                0x7B6AA5D8_5E572983_E6FB32A7_CDEBC140,
                0x27B6916A_894D3AEE_7106FE80_5FC34B44
            )
        ),
        "secp160k1": (
            0x00_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFAC73,
            0x01_00000000_00000000_0001B8FA_16DFAB9A_CA16B6B3,
            0,
            7,
            (
                0x3B4C382C_E37AA192_A4019E76_3036F4F5_DD4D7EBB,
                0x938CF935_318FDCED_6BC28286_531733C3_F03C4FEE
            )
        ),
        "secp160r1": (
            0x00_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_7FFFFFFF,
            0x01_00000000_00000000_0001F4C8_F927AED3_CA752257,
            0x00_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_7FFFFFFC,
            0x00_1C97BEFC_54BD7A8B_65ACF89F_81D4D4AD_C565FA45,
            (
                0x4A96B568_8EF57328_46646989_68C38BB9_13CBFC82,
                0x23A62855_3168947D_59DCC912_04235137_7AC5FB32
            )
        ),
        "secp160r2": (
            0x00_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFAC73,
            0x01_00000000_00000000_0000351E_E786A818_F3A1A16B,
            0x00_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFAC70,
            0x00_B4E134D3_FB59EB8B_AB572749_04664D5A_F50388BA,
            (
                0x52DCB034_293A117E_1F4FF11B_30F7199D_3144CE6D,
                0xFEAFFEF2_E331F296_E071FA0D_F9982CFE_A7D43F2E
            )
        ),
        "secp192k1": (
            0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFEE37,
            0xFFFFFFFF_FFFFFFFF_FFFFFFFE_26F2FC17_0F69466A_74DEFD8D,
            0,
            3,
            (
                0xDB4FF10E_C057E9AE_26B07D02_80B7F434_1DA5D1B1_EAE06C7D,
                0x9B2F2F6D_9C5628A7_844163D0_15BE8634_4082AA88_D95E2F9D
            )
        ),
        "secp224k1": (
            0x00_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFE56D,
            0x01_00000000_00000000_00000000_0001DCE8_D2EC6184_CAF0A971_769FB1F7,
            0,
            5,
            (
                0xA1455B33_4DF099DF_30FC28A1_69A467E9_E47075A9_0F7E650E_B6B7A45C,
                0x7E089FED_7FBA3442_82CAFBD6_F7E319F7_C0B0BD59_E2CA4BDB_556D61A5
            )
        ),
        "secp224r1": (
            0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_00000000_00000001,
            0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFF16A2_E0B8F03E_13DD2945_5C5C2A3D,
            0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFE,
            0xB4050A85_0C04B3AB_F5413256_5044B0B7_D7BFD8BA_270B3943_2355FFB4,
            (
                0xB70E0CBD_6BB4BF7F_321390B9_4A03C1D3_56C21122_343280D6_115C1D21,
                0xBD376388_B5F723FB_4C22DFE6_CD4375A0_5A074764_44D58199_85007E34
            )
        ),
        "secp256k1": (
            0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFC2F,
            0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141,
            0,
            7,
            (
                0x79BE667E_F9DCBBAC_55A06295_CE870B07_029BFCDB_2DCE28D9_59F2815B_16F81798,
                0x483ADA77_26A3C465_5DA4FBFC_0E1108A8_FD17B448_A6855419_9C47D08F_FB10D4B8
            )
        ),
        "secp384r1": (
            0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFFFF_00000000_00000000_FFFFFFFF,
            0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_C7634D81_F4372DDF_581A0DB2_48B0A77A_ECEC196A_CCC52973,
            0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFFFF_00000000_00000000_FFFFFFFC,
            0xB3312FA7_E23EE7E4_988E056B_E3F82D19_181D9C6E_FE814112_0314088F_5013875A_C656398D_8A2ED19D_2A85C8ED_D3EC2AEF,
            (
                0xAA87CA22_BE8B0537_8EB1C71E_F320AD74_6E1D3B62_8BA79B98_59F741E0_82542A38_5502F25D_BF55296C_3A545E38_72760AB7,
                0x3617DE4A_96262C6F_5D9E98BF_9292DC29_F8F41DBD_289A147C_E9DA3113_B5F0B8C0_0A60B1CE_1D7E819D_7A431D7C_90EA0E5F
            )
        ),
        "secp521r1": (
            0x01FF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF,
            0x01FF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFA_51868783_BF2F966B_7FCC0148_F709A5D0_3BB5C9B8_899C47AE_BB6FB71E_91386409,
            0x01FF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFC,
            0x0051_953EB961_8E1C9A1F_929A21A0_B68540EE_A2DA725B_99B315F3_B8B48991_8EF109E1_56193951_EC7E937B_1652C0BD_3BB1BF07_3573DF88_3D2C34F1_EF451FD4_6B503F00,
            (
                0x00C6_858E06B7_0404E9CD_9E3ECB66_2395B442_9C648139_053FB521_F828AF60_6B4D3DBA_A14B5E77_EFE75928_FE1DC127_A2FFA8DE_3348B3C1_856A429B_F97E7E31_C2E5BD66,
                0x0118_39296A78_9A3BC004_5C8A5FB4_2C7D1BD9_98F54449_579B4468_17AFBD17_273E662C_97EE7299_5EF42640_C550B901_3FAD0761_353C7086_A272C240_88BE9476_9FD16650
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

            self.public_key_length = (len(bin(self.p).replace("0b", "")) + 7) // 8
            self.order_bitlength = len(bin(self.n).replace("0b", ""))


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
            x, _ = self.jacobian.fast_multiply((x, y), private_key, secret=True)
            return self._int_to_bytes(x)


        def _subject_to_int(self, subject):
            subject = (b"\x00" + subject)[-self.order_bitlength // 8 - 1:]
            subject = bytes([subject[0] % (2 ** (self.order_bitlength % 8))]) + subject[1:]
            return self._bytes_to_int(subject)


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

            z = self._subject_to_int(subject)

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
                px, py = self.jacobian.fast_multiply(self.g, k, secret=True)

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

                rs_bus = self._int_to_bytes(r) + self._int_to_bytes(s)

                if recoverable:
                    recid = py % 2
                    recid += 2 * int(px // self.n)
                    return bytes([31 + recid]) + rs_bus
                else:
                    return rs_bus


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

            z = self._subject_to_int(subject)

            rinv = self.jacobian.inv(r, self.n)
            u1 = (-z * rinv) % self.n
            u2 = (s * rinv) % self.n

            # Recover R
            rx = r + (recid // 2) * self.n
            if rx >= self.p:
                raise ValueError("Rx is out of bounds")
            ry_mod = recid % 2

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

            x, y = self.jacobian.fast_shamir(self.g, u1, (rx, ry), u2)
            return self._int_to_bytes(x), self._int_to_bytes(y)


        def verify(self, signature, data, public_key, hash):
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

            r = self._bytes_to_int(signature[:self.public_key_length])
            s = self._bytes_to_int(signature[self.public_key_length:])

            # Verify bounds
            if r >= self.n:
                raise ValueError("r is out of bounds")
            if s >= self.n:
                raise ValueError("s is out of bounds")

            public_key = [self._bytes_to_int(c) for c in public_key]

            # Ensure that the public key is correct
            if not self.jacobian.is_on_curve(public_key):
                raise ValueError("Public key is not on curve")

            z = self._subject_to_int(subject)

            sinv = self.jacobian.inv(s, self.n)
            u1 = (z * sinv) % self.n
            u2 = (r * sinv) % self.n

            x1, y1 = self.jacobian.fast_shamir(self.g, u1, public_key, u2)
            if r != x1:
                raise ValueError("Invalid signature")

            return True


class RSA:
    pass


aes = AES()
ecc = ECC(ECCBackend())
rsa = RSA()
