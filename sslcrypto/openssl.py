import hashlib
import ctypes
import hmac
import os

lib = None


def init():
    global aes, ecc, rsa

    # Initialize functions
    lib.SSLeay_version.restype = ctypes.c_char_p

    # Initialize internal state
    lib.OPENSSL_add_all_algorithms_conf()

    aes = AES()
    ecc = ECC()
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



class ECC:
    NIDS = {
        "c2pnb163v1": 684,
        "c2pnb163v2": 685,
        "c2pnb163v3": 686,
        "c2pnb176v1": 687,
        "c2tnb191v1": 688,
        "c2tnb191v2": 689,
        "c2tnb191v3": 690,
        "c2onb191v4": 691,
        "c2onb191v5": 692,
        "c2pnb208w1": 693,
        "c2tnb239v1": 694,
        "c2tnb239v2": 695,
        "c2tnb239v3": 696,
        "c2onb239v4": 697,
        "c2onb239v5": 698,
        "c2pnb272w1": 699,
        "c2pnb304w1": 700,
        "c2tnb359v1": 701,
        "c2pnb368w1": 702,
        "c2tnb431r1": 703,
        "secp112r1": 704,
        "secp112r2": 705,
        "secp128r1": 706,
        "secp128r2": 707,
        "secp160k1": 708,
        "secp160r1": 709,
        "secp160r2": 710,
        "secp192k1": 711,
        "secp224k1": 712,
        "secp224r1": 713,
        "secp256k1": 714,
        "secp384r1": 715,
        "secp521r1": 716,
        "sect113r1": 717,
        "sect113r2": 718,
        "sect131r1": 719,
        "sect131r2": 720,
        "sect163k1": 721,
        "sect163r1": 722,
        "sect163r2": 723,
        "sect193r1": 724,
        "sect193r2": 725,
        "sect233k1": 726,
        "sect233r1": 727,
        "sect239k1": 728,
        "sect283k1": 729,
        "sect283r1": 730,
        "sect409k1": 731,
        "sect409r1": 732,
        "sect571k1": 733,
        "sect571r1": 734
    }


    def get_curve(self, name):
        if name not in self.NIDS:
            raise ValueError("Unknown curve {}".format(name))
        group = lib.EC_GROUP_new_by_curve_name(self.NIDS[name])
        if not group:
            raise ValueError("Curve {} is unsupported by OpenSSL".format(name))
        return EllipticCurve(self.NIDS[name], group)


class EllipticCurve:
    def __init__(self, nid, group):
        self.lib = lib  # For finalizer
        self.nid = nid
        self.group = group

        # Get public key length by checking order
        order_bn = lib.BN_new()
        lib.EC_GROUP_get_order(group, order_bn, None)
        self.public_key_length = (lib.BN_num_bits(order_bn) + 7) // 8
        lib.BN_free(order_bn)


    def __del__(self):
        self.lib.EC_GROUP_free(self.group)


    def _private_key_to_ec_key(self, private_key):
        eckey = lib.EC_KEY_new_by_curve_name(self.nid)
        if not eckey:
            raise ValueError("Failed to allocate EC_KEY")
        private_key_bn = lib.BN_bin2bn(private_key, len(private_key), None)
        if not lib.EC_KEY_set_private_key(eckey, private_key_bn):
            lib.EC_KEY_free(eckey)
            raise ValueError("Invalid private key")
        return eckey, private_key_bn


    def _public_key_to_ec_key(self, public_key):
        eckey = lib.EC_KEY_new_by_curve_name(self.nid)
        if not eckey:
            raise ValueError("Failed to allocate EC_KEY")
        x, y = public_key
        x_bn = lib.BN_bin2bn(x, len(x), None)
        y_bn = lib.BN_bin2bn(y, len(y), None)
        if not lib.EC_KEY_set_public_key_affine_coordinates(eckey, x_bn, y_bn):
            lib.EC_KEY_free(eckey)
            raise ValueError("Invalid private key")
        return eckey


    def _encode_public_key(self, x, y):
        return bytes([0x02 + (y[-1] % 2)]) + x


    def _point_to_affine(self, point):
        # Convert to affine coordinates
        x_bn = lib.BN_new()
        y_bn = lib.BN_new()
        try:
            if not lib.EC_POINT_get_affine_coordinates_GFp(self.group, point, x_bn, y_bn, None):
                raise ValueError("Failed to convert public key to affine coordinates")
            # Convert to binary
            if (lib.BN_num_bits(x_bn) + 7) // 8 > self.public_key_length:
                raise ValueError("Public key X coordinate is too large")
            if (lib.BN_num_bits(y_bn) + 7) // 8 > self.public_key_length:
                raise ValueError("Public key Y coordinate is too large")
            x = ctypes.create_string_buffer(self.public_key_length)
            y = ctypes.create_string_buffer(self.public_key_length)
            lib.BN_bn2bin(x_bn, x)
            lib.BN_bn2bin(y_bn, y)
            return bytes(x), bytes(y)
        finally:
            lib.BN_free(x_bn)
            lib.BN_free(y_bn)


    def _decode_public_key(self, public_key, partial=False):
        if not public_key:
            raise ValueError("No public key")

        if public_key[0] == 0x04:
            # Uncompressed. We could technically call OpenSSL here as well but
            # this would be slower
            expected_length = 1 + 2 * self.public_key_length
            if partial:
                if len(public_key) < expected_length:
                    raise ValueError("Invalid uncompressed public key length")
                x = public_key[1:1 + self.public_key_length]
                y = public_key[1 + self.public_key_length:expected_length]
                return (x, y), expected_length
            else:
                if len(public_key) != expected_length:
                    raise ValueError("Invalid uncompressed public key length")
                x = public_key[1:1 + self.public_key_length]
                y = public_key[1 + self.public_key_length:]
                return x, y
        elif public_key[0] in (0x02, 0x03):
            # Compressed
            expected_length = 1 + self.public_key_length
            if partial:
                if len(public_key) < expected_length:
                    raise ValueError("Invalid compressed public key length")
            else:
                if len(public_key) != expected_length:
                    raise ValueError("Invalid compressed public key length")
            point = lib.EC_POINT_new(self.group)
            if not point:
                raise ValueError("Could not create point")
            try:
                if not lib.EC_POINT_oct2point(self.group, point, public_key, expected_length, None):
                    raise ValueError("Invalid compressed public key")
                x, y = self._point_to_affine(point)
                # Sanity check
                if x != public_key[1:expected_length]:
                    raise ValueError("Incorrect compressed public key")
                if partial:
                    return (x, y), expected_length
                else:
                    return x, y
            finally:
                lib.EC_POINT_free(point)
        else:
            raise ValueError("Invalid public key prefix")


    def new_private_key(self):
        # Create random key
        eckey = lib.EC_KEY_new_by_curve_name(self.nid)
        lib.EC_KEY_generate_key(eckey)
        # To big integer
        private_key_bn = lib.EC_KEY_get0_private_key(eckey)
        # To binary
        private_key = ctypes.create_string_buffer((lib.BN_num_bits(private_key_bn) + 7) // 8)
        lib.BN_bn2bin(private_key_bn, private_key)
        # Cleanup
        lib.EC_KEY_free(eckey)
        return bytes(private_key)


    def private_to_public(self, private_key):
        eckey, private_key_bn = self._private_key_to_ec_key(private_key)
        try:
            # Derive public key
            point = lib.EC_POINT_new(self.group)
            try:
                if not lib.EC_POINT_mul(self.group, point, private_key_bn, None, None, None):
                    raise ValueError("Failed to derive public key")
                x, y = self._point_to_affine(point)
                return self._encode_public_key(bytes(x), bytes(y))
            finally:
                lib.EC_POINT_free(point)
        finally:
            lib.EC_KEY_free(eckey)


    def derive(self, private_key, public_key):
        if not isinstance(public_key, tuple):
            public_key = self._decode_public_key(public_key)

        # Private key:
        # Create EC_KEY
        eckey, _ = self._private_key_to_ec_key(private_key)
        try:
            # Convert to EVP_PKEY
            pkey = lib.EVP_PKEY_new()
            if not pkey:
                raise ValueError("Could not create private key object")
            try:
                lib.EVP_PKEY_set1_EC_KEY(pkey, eckey)

                # Public key:
                # Create EC_KEY
                peer_eckey = self._public_key_to_ec_key(public_key)
                try:
                    # Convert to EVP_PKEY
                    peer_pkey = lib.EVP_PKEY_new()
                    if not peer_pkey:
                        raise ValueError("Could not create public key object")
                    try:
                        lib.EVP_PKEY_set1_EC_KEY(peer_pkey, peer_eckey)

                        # Create context
                        ctx = lib.EVP_PKEY_CTX_new(pkey, None)
                        if not ctx:
                            raise ValueError("Could not create EVP context")
                        try:
                            if lib.EVP_PKEY_derive_init(ctx) != 1:
                                raise ValueError("Could not initialize key derivation")
                            if not lib.EVP_PKEY_derive_set_peer(ctx, peer_pkey):
                                raise ValueError("Could not set peer")

                            # Actually derive
                            key_len = ctypes.c_int(0)
                            lib.EVP_PKEY_derive(ctx, None, ctypes.byref(key_len))
                            key = ctypes.create_string_buffer(key_len.value)
                            lib.EVP_PKEY_derive(ctx, key, ctypes.byref(key_len))

                            return bytes(key)
                        finally:
                            lib.EVP_PKEY_CTX_free(ctx)
                    finally:
                        lib.EVP_PKEY_free(peer_pkey)
                finally:
                    lib.EC_KEY_free(peer_eckey)
            finally:
                lib.EVP_PKEY_free(pkey)
        finally:
            lib.EC_KEY_free(eckey)


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
        ciphertext, iv = aes.encrypt(data, k_enc, algo=algo)
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

        return aes.decrypt(ciphertext, iv, k_enc)


class RSA:
    pass
