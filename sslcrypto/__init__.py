from . import library

__all__ = ["aes", "ecies", "rsa"]

lib = library.discoverLibrary()
if lib:
	from . import openssl
	openssl.lib = lib
	openssl.init()
	aes, ecies, rsa = openssl.aes, openssl.ecies, openssl.rsa
else:
	from .fallback import aes, ecies, rsa
