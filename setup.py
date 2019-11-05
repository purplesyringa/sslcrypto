from setuptools import setup

setup(
    name="sslcrypto",
    version="1.0",
    description="ECIES, AES and RSA OpenSSL-based implementation with fallback",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Ivanq",
    author_email="imachug@gmail.com",
    url="https://github.com/imachug/sslcrypto",
    packages=["sslcrypto"],
    install_requires=[
        "pyaes==1.6.1",
        "ecdsa==0.13.3"
    ]
)