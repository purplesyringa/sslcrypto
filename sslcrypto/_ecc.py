import hashlib
import hmac


class ECC:
    CURVES = (
        "ed25519",
        "secp112r1", "secp112r2",
        "secp128r1", "secp128r2",
        "secp160k1", "secp160r1", "secp160r2",
        "secp192k1",
        "secp224k1", "secp224r1",
        "secp256k1",
        "secp384r1",
        "secp521r1"
    )

    def __init__(self, backend):
        self._backend = backend


    def get_curve(self, name):
        if name not in self.CURVES or not self._backend.is_supported(name):
            raise ValueError("Unknown curve {}".format(name))
        return EllipticCurve(self._backend, name)


class EllipticCurve:
    def __init__(self, backend, name):
        self._backend = backend.EllipticCurveBackend(name)
        self.name = name


    def _encode_public_key(self, x, y):
        return bytes([0x02 + (y[-1] % 2)]) + x


    def _decode_public_key(self, public_key, partial=False):
        if not public_key:
            raise ValueError("No public key")

        if public_key[0] == 0x04:
            # Uncompressed
            expected_length = 1 + 2 * self._backend.public_key_length
            if partial:
                if len(public_key) < expected_length:
                    raise ValueError("Invalid uncompressed public key length")
                x = public_key[1:1 + self._backend.public_key_length]
                y = public_key[1 + self._backend.public_key_length:expected_length]
                return (x, y), expected_length
            else:
                if len(public_key) != expected_length:
                    raise ValueError("Invalid uncompressed public key length")
                x = public_key[1:1 + self._backend.public_key_length]
                y = public_key[1 + self._backend.public_key_length:]
                return x, y
        elif public_key[0] in (0x02, 0x03):
            # Compressed
            expected_length = 1 + self._backend.public_key_length
            if partial:
                if len(public_key) < expected_length:
                    raise ValueError("Invalid compressed public key length")
            else:
                if len(public_key) != expected_length:
                    raise ValueError("Invalid compressed public key length")

            x, y = self._backend.decompress_point(public_key[:expected_length])
            # Sanity check
            if x != public_key[1:expected_length]:
                raise ValueError("Incorrect compressed public key")
            if partial:
                return (x, y), expected_length
            else:
                return x, y
        else:
            raise ValueError("Invalid public key prefix")


    def new_private_key(self):
        return self._backend.new_private_key()


    def private_to_public(self, private_key):
        x, y = self._backend.private_to_public(private_key)
        return self._encode_public_key(x, y)


    def derive(self, private_key, public_key):
        if not isinstance(public_key, tuple):
            public_key = self._decode_public_key(public_key)
        return self._backend.ecdh(private_key, public_key)


    # High-level functions
    def encrypt(self, data, public_key, algo="aes-256-cbc", derivation="sha256", mac="hmac-sha256"):
        # Generate ephemeral private key
        private_key = self.new_private_key()

        # Derive key
        ecdh = self.derive(private_key, public_key)
        if callable(derivation):
            key = derivation(ecdh)
        elif derivation == "sha256":  # Most commonly used
            hash = hashlib.sha256()
            hash.update(ecdh)
            key = hash.digest()
        elif derivation == "sha512":  # Sometimes used as well
            hash = hashlib.sha512()
            hash.update(ecdh)
            key = hash.digest()
        else:
            raise ValueError("Unsupported key derivation method")
        k_enc, k_mac = key[:32], key[32:]

        # Encrypt
        ciphertext, iv = self._backend.aes.encrypt(data, k_enc, algo=algo)
        ciphertext = iv + self.private_to_public(private_key) + ciphertext

        # Add MAC tag
        if callable(mac):
            tag = mac(k_mac, ciphertext)
        elif mac == "hmac-sha256":
            h = hmac.new(k_mac, digestmod="sha256")
            h.update(ciphertext)
            tag = h.digest()
        elif mac == "hmac-sha512":
            h = hmac.new(k_mac, digestmod="sha512")
            h.update(ciphertext)
            tag = h.digest()
        elif mac is False:
            tag = b""
        else:
            raise ValueError("Unsupported MAC")

        return ciphertext + tag


    def decrypt(self, ciphertext, private_key, algo="aes-256-cbc", derivation="sha256", mac="hmac-sha256"):
        # Get MAC tag
        if callable(mac):
            tag_length = mac.digest_size
        elif mac == "hmac-sha256":
            tag_length = hmac.new(b"", digestmod="sha256").digest_size
        elif mac == "hmac-sha512":
            tag_length = hmac.new(b"", digestmod="sha512").digest_size
        elif mac is False:
            tag_length = 0
        else:
            raise ValueError("Unsupported MAC")

        if len(ciphertext) < tag_length:
            raise ValueError("Ciphertext is too small to contain MAC tag")
        ciphertext, tag = ciphertext[:-tag_length], ciphertext[-tag_length:]

        orig_ciphertext = ciphertext

        if len(ciphertext) < 16:
            raise ValueError("Ciphertext is too small to contain IV")
        iv, ciphertext = ciphertext[:16], ciphertext[16:]

        public_key, pos = self._decode_public_key(ciphertext, partial=True)
        ciphertext = ciphertext[pos:]

        # Derive key
        ecdh = self.derive(private_key, public_key)
        if callable(derivation):
            key = derivation(ecdh)
        elif derivation == "sha256":  # Most commonly used
            hash = hashlib.sha256()
            hash.update(ecdh)
            key = hash.digest()
        elif derivation == "sha512":  # Sometimes used as well
            hash = hashlib.sha512()
            hash.update(ecdh)
            key = hash.digest()
        else:
            raise ValueError("Unsupported key derivation method")
        k_enc, k_mac = key[:32], key[32:]

        # Verify MAC tag
        if callable(mac):
            expected_tag = mac(k_mac, orig_ciphertext)
        elif mac == "hmac-sha256":
            h = hmac.new(k_mac, digestmod="sha256")
            h.update(orig_ciphertext)
            expected_tag = h.digest()
        elif mac == "hmac-sha512":
            h = hmac.new(k_mac, digestmod="sha512")
            h.update(orig_ciphertext)
            expected_tag = h.digest()
        elif mac is False:
            expected_tag = b""

        if not hmac.compare_digest(tag, expected_tag):
            raise ValueError("Invalid MAC tag")

        return self._backend.aes.decrypt(ciphertext, iv, k_enc)


    def sign(self, data, private_key, hash="sha256", recoverable=False):
        return self._backend.sign(data, private_key, hash, recoverable)


    def recover(self, signature, data, hash="sha256"):
        # Sanity check: is this signature recoverable?
        if len(signature) != 1 + 2 * self._backend.public_key_length:
            raise ValueError("Cannot recover an unrecoverable signature")
        x, y = self._backend.recover(signature, data, hash)
        return self._encode_public_key(x, y)
