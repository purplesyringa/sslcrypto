from sslcrypto import aes, ecc
from .conf import parallelize

curve = ecc.get_curve("secp256k1")


def test_aes():
    @parallelize(8)
    def run():
        for _ in range(100):
            key1 = aes.new_key()
            key2 = aes.new_key()
            data = b"Hello, world!"

            assert aes.decrypt(*aes.encrypt(data, key1), key=key1) == data
            try:
                aes.decrypt(*aes.encrypt(data, key1), key=key2)
            except ValueError:
                pass

    run()


def test_ecc_basic():
    @parallelize(8)
    def run():
        priv = b"8\"\x7f\xdf\np\xd1s\x809\xc4\xd0\xd2\xd4Z\x85La{\x08\xb3\xc9[\x9c+ji\xfeA,\x14+"

        # Basic conversions
        for _ in range(100):
            pub = curve.private_to_public(priv)
            assert pub == b"\x03\xce\x1c\xb7\x17\xce1\x99\x0cOj\xfe\xc0D\x1c+n\xa1\xe7\x88\xbe\xfa5\xad\xaf\xad\x1c\x05R\xc8\xf3\xa1\x90"

        # WIF
        for _ in range(100):
            assert curve.private_to_wif(priv) == b"5JF1U8yr5wZbrBCgTVtswjMR7iqC8KQ4oh4EPqeKRmnSompJVMQ"
        for _ in range(100):
            assert curve.wif_to_private(b"5JF1U8yr5wZbrBCgTVtswjMR7iqC8KQ4oh4EPqeKRmnSompJVMQ") == priv

        # Addresses
        for _ in range(100):
            assert curve.public_to_address(pub) == curve.private_to_address(priv) == b"1553rYBLgCVA6vGYcN7AipdAeWGp9tkAw4"
            assert curve.private_to_address(priv, is_compressed=False) == b"1G1ZCdmQUuhnn8zYrx2Q2hXMB5NjsbZ3k7"

        # BIP32
        for _ in range(100):
            assert curve.derive_child(priv, 0) == b"*-\x0b\xcd\x14|l-\x8d\x07\x15N\xdbX\xaa\x92\x12\n\x8cU\x8d2-\x00\x13\xa2:\x11UFV*"
            assert curve.derive_child(priv, 100) == b"{N*\xa4\xd3\xa2\xea\xe0\x8c\xbbo\xaar\x91\x86\x88e\x85\x83\xb9\xeb}\xf7\xe6\x01\x80\xc1\xde`\xa1\xe3\x1d"


    run()


def test_ecdh():
    @parallelize(8)
    def run():
        priv1 = b"8\"\x7f\xdf\np\xd1s\x809\xc4\xd0\xd2\xd4Z\x85La{\x08\xb3\xc9[\x9c+ji\xfeA,\x14+"
        priv2 = b"\x83|0\xf7\x04\xc0\xde7\t\x1b\x96\xe9\x05\xe4_o\xe1\xb7\x12\x93\x90,\x03\x87\xc3\xf5\xfa_\x17-c\x95"
        for _ in range(100):
            assert curve.derive(priv1, pub2) == curve.derive(priv2, pub1) == b"\xb2\xab\x1d\xb4\x9dBX\x81\xc6\xf2\x15]+\xc0\x85\xc7\xe9\x018G\xe1\xda\x18\xf4\xac\xaa\x00q\x1d\xc6+\x04"


    run()


def test_ecdsa():
    @parallelize(8)
    def run():
        priv1 = b"8\"\x7f\xdf\np\xd1s\x809\xc4\xd0\xd2\xd4Z\x85La{\x08\xb3\xc9[\x9c+ji\xfeA,\x14+"
        priv2 = b"\x83|0\xf7\x04\xc0\xde7\t\x1b\x96\xe9\x05\xe4_o\xe1\xb7\x12\x93\x90,\x03\x87\xc3\xf5\xfa_\x17-c\x95"
        data = b"Hello, world!"
        entropy = b"Just some entropy"

        signature = b"\x1f\x14\xc4\x95z7-\xaf\x91T&\xa7\xd0\xfc\x9b\x8b\x08\x15g\xa1\x82[\x08\x91o\xe1.\x8d\xb6=\x1a\x88\xe07\x01\xf39\xe5j~\xd5#\xd2\xbc\x88 \x16Ts\xac\x9dI\x0f.\xe8aCT8H\\\xb7pb-"
        for _ in range(100):
            assert curve.sign(data, priv1, recoverable=True, entropy=entropy) == signature
            assert curve.sign(data, priv1, entropy=entropy) == signature[1:]
            assert curve.verify(signature, data, pub1)
            assert curve.verify(signature[1:], data, pub1)
            assert curve.recover(signature, data) == pub1

        signature = b"\x1b\x14\xc4\x95z7-\xaf\x91T&\xa7\xd0\xfc\x9b\x8b\x08\x15g\xa1\x82[\x08\x91o\xe1.\x8d\xb6=\x1a\x88\xe07\x01\xf39\xe5j~\xd5#\xd2\xbc\x88 \x16Ts\xac\x9dI\x0f.\xe8aCT8H\\\xb7pb-"
        for _ in range(100):
            pub1_uncompressed = curve.private_to_public(priv1, is_compressed=False)
            assert curve.sign(data, priv1, recoverable=True, is_compressed=False, entropy=entropy) == signature
            assert curve.sign(data, priv1, is_compressed=False, entropy=entropy) == signature[1:]
            assert curve.verify(signature, data, pub1)
            assert curve.verify(signature[1:], data, pub1)
            assert curve.verify(signature, data, pub1_uncompressed)
            assert curve.verify(signature[1:], data, pub1_uncompressed)
            assert curve.recover(signature, data) == pub1_uncompressed


    run()


def test_ecies():
    @parallelize(8)
    def run():
        priv = b"8\"\x7f\xdf\np\xd1s\x809\xc4\xd0\xd2\xd4Z\x85La{\x08\xb3\xc9[\x9c+ji\xfeA,\x14+"
        pub = curve.private_to_public(priv)
        data = b"Hello, world!"

        for _ in range(100):
            ciphertext = curve.encrypt(data, pub)
            assert curve.decrypt(ciphertext, priv) == data


    run()
