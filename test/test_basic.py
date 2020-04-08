import pytest
import sslcrypto
import sslcrypto.fallback


eccs = [sslcrypto.fallback.ecc]
ecc_ids = ["fallback"]
if sslcrypto.ecc is not sslcrypto.fallback.ecc:
    eccs.append(sslcrypto.ecc)
    ecc_ids.append("native")

curves, curve_ids = [], []
for name in sslcrypto.ecc.CURVES:
    # Pure-Python implementation
    curves.append(sslcrypto.fallback.ecc.get_curve(name))
    curve_ids.append("fallback-{}".format(name))

    # Try testing native version as well
    if sslcrypto.ecc is not sslcrypto.fallback.ecc:
        curves.append(sslcrypto.ecc.get_curve(name))
        curve_ids.append("native-{}".format(name))


@pytest.mark.parametrize("curve", curves, ids=curve_ids)
def test(curve):
    priv1 = curve.new_private_key()
    pub1 = curve.private_to_public(priv1)
    pub1_compressed = curve.private_to_public(priv1 + b"\x01")
    priv2 = curve.new_private_key()
    pub2 = curve.private_to_public(priv2)
    pub2_compressed = curve.private_to_public(priv2 + b"\x01")
    priv3 = curve.new_private_key()
    pub3 = curve.private_to_public(priv3)
    data = b"Hello, world!"
    data2 = b"Just a test"

    # WIF
    assert curve.wif_to_private(curve.private_to_wif(priv1)) == priv1

    # ECDH
    assert curve.derive(priv1, pub2) == curve.derive(priv2, pub1)
    assert curve.derive(priv1, pub2) != curve.derive(priv3, pub1)

    # ECIES
    for algo in ("aes-128-ctr", "aes-192-ofb", "aes-256-cbc"):
        for derivation in ("sha256", "sha512"):
            for mac in ("hmac-sha256", "hmac-sha512", None):
                params = {"algo": algo, "derivation": derivation, "mac": mac}

                ciphertext = curve.encrypt(data, pub1, **params)
                assert curve.decrypt(ciphertext, priv1, **params) == data
                with pytest.raises(ValueError):
                    if curve.decrypt(ciphertext, priv2, **params) != data:
                        # We have to handle this case separately because AES might
                        # accidentally manage to decrypt data with a wrong key
                        raise ValueError("Got wrong data")

    # ECDSA
    for hash in ("sha256", "sha1"):
        signature = curve.sign(data, priv1, hash=hash)
        signature_compressed = curve.sign(data, priv1 + b"\x01", hash=hash)
        rec_signature = curve.sign(data, priv1 + b"\x01", hash=hash, recoverable=True)

        assert curve.recover(rec_signature, data, hash=hash) == pub1_compressed
        assert curve.verify(signature, data, pub1, hash=hash)
        assert curve.verify(signature_compressed, data, pub1_compressed, hash=hash)
        assert curve.verify(rec_signature, data, pub1_compressed, hash=hash)

        # Unrecoverable signature
        with pytest.raises(ValueError):
            curve.recover(signature, data, hash=hash)
        # Wrong data
        curve.recover(rec_signature, data2, hash=hash) != pub1_compressed
        # Wrong public key
        with pytest.raises(ValueError):
            curve.verify(signature, data, pub2_compressed, hash=hash)
        # Wrong data
        with pytest.raises(ValueError):
            curve.verify(signature, data2, pub1_compressed, hash=hash)


@pytest.mark.parametrize("ecc", eccs, ids=ecc_ids)
def test_static(ecc):
    curve = ecc.get_curve("secp256k1")

    priv1 = b"8\"\x7f\xdf\np\xd1s\x809\xc4\xd0\xd2\xd4Z\x85La{\x08\xb3\xc9[\x9c+ji\xfeA,\x14+"
    priv2 = b"\x83|0\xf7\x04\xc0\xde7\t\x1b\x96\xe9\x05\xe4_o\xe1\xb7\x12\x93\x90,\x03\x87\xc3\xf5\xfa_\x17-c\x95"
    data = b"Hello, world!"
    entropy = b"Just some entropy"

    # Basic conversions
    pub1 = curve.private_to_public(priv1)
    pub2 = curve.private_to_public(priv2)
    pub1_compressed = curve.private_to_public(priv1 + b"\x01")
    pub2_compressed = curve.private_to_public(priv2 + b"\x01")
    assert pub1 == b"\x04\xce\x1c\xb7\x17\xce1\x99\x0cOj\xfe\xc0D\x1c+n\xa1\xe7\x88\xbe\xfa5\xad\xaf\xad\x1c\x05R\xc8\xf3\xa1\x90\xb5\x004\xcc\xb9\x1chG\xb0\x17S\xe6\xaf\xed\xca\x9f\x8c\x07\xa3%\xa4%uB\x005\xb9\xc4\x97\x89\x81\xe3"
    assert pub2 == b"\x04n\xb8g\x18\xc3\xa8o\x85\x92\xaa\xcax\x10c\x0c[\xc1x\xc0\x94\xa5!A\xd6\x12\x8e\x01\xee\xf52\x7fb\xf3\xb7{\xf8,\xc4n\x10#$9\xbe\xa6\xba\x13=\xa0eZ\x99\x99\xc4dgdlN\xbe\xf4\x05\x18\xad"
    assert pub1_compressed == b"\x03\xce\x1c\xb7\x17\xce1\x99\x0cOj\xfe\xc0D\x1c+n\xa1\xe7\x88\xbe\xfa5\xad\xaf\xad\x1c\x05R\xc8\xf3\xa1\x90"
    assert pub2_compressed == b"\x03n\xb8g\x18\xc3\xa8o\x85\x92\xaa\xcax\x10c\x0c[\xc1x\xc0\x94\xa5!A\xd6\x12\x8e\x01\xee\xf52\x7fb"

    # WIF
    assert curve.private_to_wif(priv1) == b"5JF1U8yr5wZbrBCgTVtswjMR7iqC8KQ4oh4EPqeKRmnSompJVMQ"
    assert curve.wif_to_private(b"5JpCC7mMHxZ8Lw9TwUymMzdcfWeLVi8r8Tyyz5ic6G12iqAXr6E") == priv2

    # Addresses
    assert curve.public_to_address(pub1) == curve.private_to_address(priv1) == b"1G1ZCdmQUuhnn8zYrx2Q2hXMB5NjsbZ3k7"
    assert curve.public_to_address(pub1_compressed) == curve.private_to_address(priv1 + b"\x01") == b"1553rYBLgCVA6vGYcN7AipdAeWGp9tkAw4"
    assert curve.public_to_address(pub2) == curve.private_to_address(priv2) == b"1Dj1pAV83cDLZPxYhKfnbDMigKVxML6KPj"
    assert curve.public_to_address(pub2_compressed) == curve.private_to_address(priv2 + b"\x01") == b"1JCQGE4mVQ2DnEZEdVJJnAkMdEPjqVDNtc"

    # ECDH
    assert curve.derive(priv1, pub2) == curve.derive(priv2, pub1) == b"\xb2\xab\x1d\xb4\x9dBX\x81\xc6\xf2\x15]+\xc0\x85\xc7\xe9\x018G\xe1\xda\x18\xf4\xac\xaa\x00q\x1d\xc6+\x04"

    # ECDSA
    signature = b"\x1f\x14\xc4\x95z7-\xaf\x91T&\xa7\xd0\xfc\x9b\x8b\x08\x15g\xa1\x82[\x08\x91o\xe1.\x8d\xb6=\x1a\x88\xe07\x01\xf39\xe5j~\xd5#\xd2\xbc\x88 \x16Ts\xac\x9dI\x0f.\xe8aCT8H\\\xb7pb-"
    assert curve.sign(data, priv1 + b"\x01", recoverable=True, entropy=entropy) == signature
    assert curve.sign(data, priv1 + b"\x01", entropy=entropy) == signature[1:]
    assert curve.verify(signature, data, pub1_compressed)
    assert curve.verify(signature[1:], data, pub1_compressed)
    assert curve.recover(signature, data) == pub1_compressed

    signature = b"\x1b\x14\xc4\x95z7-\xaf\x91T&\xa7\xd0\xfc\x9b\x8b\x08\x15g\xa1\x82[\x08\x91o\xe1.\x8d\xb6=\x1a\x88\xe07\x01\xf39\xe5j~\xd5#\xd2\xbc\x88 \x16Ts\xac\x9dI\x0f.\xe8aCT8H\\\xb7pb-"
    assert curve.sign(data, priv1, recoverable=True, entropy=entropy) == signature
    assert curve.sign(data, priv1, entropy=entropy) == signature[1:]
    assert curve.verify(signature, data, pub1_compressed)
    assert curve.verify(signature[1:], data, pub1_compressed)
    assert curve.verify(signature, data, pub1)
    assert curve.verify(signature[1:], data, pub1)
    assert curve.recover(signature, data) == pub1

    # BIP32
    assert curve.derive_child(priv1, 0) == b"*-\x0b\xcd\x14|l-\x8d\x07\x15N\xdbX\xaa\x92\x12\n\x8cU\x8d2-\x00\x13\xa2:\x11UFV*"
    assert curve.derive_child(priv1, 100) == b"{N*\xa4\xd3\xa2\xea\xe0\x8c\xbbo\xaar\x91\x86\x88e\x85\x83\xb9\xeb}\xf7\xe6\x01\x80\xc1\xde`\xa1\xe3\x1d"

    # Additional weird cases
    data = b"F\x97\x045\xa5a\x15%J\xf7\x1d\x04\xf1\xb1\x85\xf2\xfet\xb4\xcb\x02\xab\x0b\xa2?P\x07\xd6\x13\x86x\xdb"
    privatekey = b"\x8b\xec\xd2F\xc6:A{\xf0|\x11\xadv\xcc\xaa#\xb0U\xf5\xdb\x0f1=3\xe3P\xfeW\x95\xf3\x17\xb3"
    publickey = curve.private_to_public(privatekey)
    signature = b"\x1bQ\x97h6\xaeg\xcb\xd7\xfc\xdfI\x9f\xe3\x11\x88i\xbd\x87\xe2=\xe35!\x0esX\x15\xaa\x8c\x1a\xe3\xa2\x04p~\x92\x9e\x1cD\xf6N/\xb9u\xca\xa2\xb9\x04v\xba'\xe5\xbd\xed\xb3#\xbd5\xed\xc79c\xa7\xac"
    assert curve.sign(data, privatekey, recoverable=True, hash=None) == signature
    assert curve.verify(signature, data, publickey, hash=None)
    assert curve.recover(signature, data, hash=None) == publickey

    # Parameters
    assert curve.params["n"] == 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141