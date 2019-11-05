from . import library

__all__ = ["aes", "ecc", "rsa"]

lib = library.discoverLibrary()
if lib:
	from . import openssl
	openssl.lib = lib
	openssl.init()
	aes, ecc, rsa = openssl.aes, openssl.ecc, openssl.rsa
else:
	from .fallback import aes, ecc, rsa
