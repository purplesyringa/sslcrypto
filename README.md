# sslcrypto

[![Actions Status](https://github.com/imachug/sslcrypto/workflows/tests/badge.svg)](https://github.com/imachug/sslcrypto/actions)
![Code Quality](https://raw.githubusercontent.com/imachug/sslcrypto/gh-action/quality.svg?sanitize=true)
![Code Coverage](https://raw.githubusercontent.com/imachug/sslcrypto/gh-action/coverage.svg?sanitize=true)
[![PyPI](https://img.shields.io/pypi/v/sslcrypto)](https://pypi.org/project/sslcrypto/)

**sslcrypto** is a fast and simple library for AES, ECIES and ECDSA for Python.

License: MIT + BSD-2 for ripemd implementation (see `_ripemd.py`).


## Why?

**sslcrypto** can use OpenSSL in case it's available in your system for speedup,
but pure-Python code is also available and is heavily optimized.

**N.B.** There are alternatives like coincurve which are faster in some cases
(e.g. when using secp256k1). They don't include ECIES implementation and some
useful ECDSA features and are specialized on a single curve. If that's enough
for you and libsecp256k1 bindings are available for all OSes you need to
support, use those libraries. [Coincurve](https://github.com/ofek/coincurve),
in particular, ships pre-compiled packages for all major OSes and building from
source does not require an existing libsecp256k1 installation.

**N.B.** While there are other mature cryptography libraries, they are too heavy
for simple stuff and require OpenSSL that is not available by default on Windows
(most likely many other OSes as well). That said, in case you're processing
*big* data, not *much* data, the speed advantage you get from libraries is too
small to use heavy alternatives.


## Installation

```
pip install sslcrypto
```

Additionally, you can download this repository and run
`python setup.py install`.


## Usage

### AES

```python
import sslcrypto

# Generate random key
key = sslcrypto.aes.new_key()

# Encrypt something
data = b"Hello, world!"
ciphertext, iv = sslcrypto.aes.encrypt(data, key)

# Decrypt
assert sslcrypto.aes.decrypt(ciphertext, iv, key) == data
```

By default, aes-256-cbc cipher is used. You can specify another one if you want.
The following ciphers are supported:

- aes-128-cbc, aes-192-cbc, aes-256-cbc
- aes-128-ctr, aes-192-ctr, aes-256-ctr
- aes-128-cfb, aes-192-cfb, aes-256-cfb
- aes-128-ofb, aes-192-ofb, aes-256-ofb

```python
import sslcrypto

# Generate random key
key = sslcrypto.aes.new_key(algo="aes-192-cfb")

# Encrypt something
data = b"Hello, world!"
ciphertext, iv = sslcrypto.aes.encrypt(data, key, algo="aes-192-cfb")

# Decrypt
assert sslcrypto.aes.decrypt(ciphertext, iv, key, algo="aes-192-cfb") == data
```


### ECIES

The following curves are supported:

- secp112r1, secp112r2
- secp128r1, secp128r2
- secp160k1, secp160r1, secp160r2
- secp192k1, prime192v1
- secp224k1, secp224r1
- secp256k1, prime256v1
- secp384r1
- secp521r1

Please tell me if you want to add any other curves.

```python
import sslcrypto

# Create curve object
curve = sslcrypto.ecc.get_curve("secp256k1")

# Generate private key, both compressed and uncompressed keys are supported
private_key = curve.new_private_key(is_compressed=True)

# Find a matching public key
public_key = curve.private_to_public(private_key)

# If required, you can change public key format to whatever you want
x, y = curve.decode_public_key(public_key)
electrum_public_key = x + y

# Encrypt something. You can specify a cipher if you want to, aes-256-cbc is the
# default value
data = b"Hello, world!"
ciphertext = curve.encrypt(data, public_key, algo="aes-256-ofb")

# Decrypt
assert curve.decrypt(ciphertext, private_key, algo="aes-256-ofb") == data
```


### ECDSA

```python
import sslcrypto

# Create curve object
curve = sslcrypto.ecc.get_curve("secp256k1")

# Generate private key
private_key = curve.new_private_key()

# Find a matching public key
public_key = curve.private_to_public(private_key)

# Sign something
data = b"Hello, world!"
signature = curve.sign(data, private_key)

# Verify
assert curve.verify(signature, data, public_key) == True  # Would raise on error
```

Additionally, you can create recoverable signatures:

```python
import sslcrypto

# Create curve object
curve = sslcrypto.ecc.get_curve("secp256k1")

# Generate private key
private_key = curve.new_private_key()

# Find a matching public key
public_key = curve.private_to_public(private_key)

# Sign something
data = b"Hello, world!"
signature = curve.sign(data, private_key, recoverable=True)

# Recover public key
assert curve.recover(signature, data) == public_key  # Would raise on error
```


### Bitcoin-related functions

```python
import sslcrypto
curve = sslcrypto.ecc.get_curve("secp256k1")
private_key = curve.new_private_key()
public_key = curve.private_to_public(private_key)

wif = curve.private_to_wif(private_key)  # Transform to mainnet private key
assert curve.wif_to_private(wif) == private_key

address = curve.private_to_address(private_key)
assert address == curve.public_to_address(public_key)

# Based on BIP32. Hardened indexes aren't supported yet
curve.child_derive(private_key, 123)
```


### Misc

```python
import sslcrypto
print(sslcrypto.ecc.get_backend())  # Either "fallback" or OpenSSL info
```

You can override OpenSSL path discovery:

```python
from sslcrypto.openssl import discovery
discovery.discover = lambda: ["openssl_lib.dll"]
```


## Running tests

sslcrypto uses pytest framework. Install it with pip and run `python3 -m pytest
test` in sslcrypto repository.
