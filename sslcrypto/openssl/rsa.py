from .library import lib, openssl_backend


class RSA:
    def get_backend(self):
        return openssl_backend


rsa = RSA()
