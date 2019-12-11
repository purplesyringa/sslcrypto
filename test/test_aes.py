import pytest
import sslcrypto
import sslcrypto.fallback
from .conf import parallelize


testcases = [sslcrypto.fallback.aes]
if sslcrypto.aes is not sslcrypto.fallback.aes:
    testcases.append(sslcrypto.aes)


@pytest.mark.parametrize("cipher_type", ["cbc", "ctr", "cfb", "ofb"])
@pytest.mark.parametrize("key_length", [128, 192, 256])
@pytest.mark.parametrize("aes", testcases, ids=["fallback-aes", "native-aes"][:len(testcases)])
def test(aes, key_length, cipher_type):
    algo = "aes-{}-{}".format(key_length, cipher_type)

    key1 = aes.new_key(algo=algo)
    key2 = aes.new_key(algo=algo)
    data = b"Hello, world!"

    assert aes.decrypt(*aes.encrypt(data, key1, algo=algo), key=key1, algo=algo) == data

    # We have to use if because AES might accidentally managed to decrypt data
    # with a wrong key
    with pytest.raises(ValueError):
        if aes.decrypt(*aes.encrypt(data, key1, algo=algo), key=key2, algo=algo) != data:
            raise ValueError("Got wrong data")



def test_thread_safety():
    aes = sslcrypto.aes

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
