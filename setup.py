from setuptools import setup, find_packages

setup(
    name="sslcrypto",
    version="5.2",
    description="ECIES, AES and RSA OpenSSL-based implementation with fallback",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Ivanq",
    author_email="imachug@gmail.com",
    url="https://github.com/imachug/sslcrypto",
    packages=find_packages(),
    install_requires=[
        "pyaes==1.6.1",
        "base58==1.0.3"
    ]
)