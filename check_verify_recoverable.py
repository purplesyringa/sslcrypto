import sslcrypto

curve = sslcrypto.ecc.get_curve("brainpoolP256r1")

private_key = curve.new_private_key()
public_key = curve.private_to_public(private_key)

data = b"Hello, World"
signature = curve.sign(data, private_key, recoverable=True)

# Verify
print(public_key.hex())
print(curve.verify(signature, b"Hello, world!"))
print(curve.verify(signature, b"Goodbye, world!", public_key))
print(curve.verify(signature, b"Hello, world!", public_key))

#Errors out here, as expected
print(curve.verify(signature, b"Goodbye, world!", public_key) == True)
