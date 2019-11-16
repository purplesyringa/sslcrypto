import os
import sys
import ctypes
import ctypes.util


# Discover OpenSSL library
def discover_paths():
    # Search local files first
    if "win" in sys.platform:
        # Windows
        openssl_paths = [
            os.path.abspath("libeay32.dll")
        ]
    elif "darwin" in sys.platform:
        # Mac OS
        openssl_paths = [
            os.path.abspath("libcrypto.dylib"),
            "/usr/local/opt/openssl/lib/libcrypto.dylib"
        ]
        if hasattr(sys, "_MEIPASS") and "RESOURCEPATH" in os.environ:
            names = [
                "libcrypto.dylib",
                "libcrypto.1.1.0.dylib",
                "libcrypto.1.0.2.dylib",
                "libcrypto.1.0.1.dylib",
                "libcrypto.1.0.0.dylib",
                "libcrypto.0.9.8.dylib"
            ]
            openssl_paths += [os.path.abspath(name) for name in names]
            openssl_paths += [
                os.path.join(os.environ["RESOURCEPATH"], "..", "Frameworks", name)
                for name in names
            ]
    else:
        # Linux, BSD and such
        names = [
            "libcrypto.so",
            "libssl.so",
            "libcrypto.so.1.1.0",
            "libssl.so.1.1.0",
            "libcrypto.so.1.0.2",
            "libssl.so.1.0.2",
            "libcrypto.so.1.0.1",
            "libssl.so.1.0.1",
            "libcrypto.so.1.0.0",
            "libssl.so.1.0.0",
            "libcrypto.so.0.9.8",
            "libssl.so.0.9.8"
        ]
        openssl_paths = [os.path.abspath(name) for name in names]

    if hasattr(sys, "_MEIPASS") and "darwin" not in sys.platform:
        # Bundled. Assume the same libraries in the same directory
        # pylint: disable=no-member,protected-access
        openssl_paths += [os.path.join(sys._MEIPASS, path) for path in openssl_paths]

    if "win" in sys.platform:
        openssl_paths.append(ctypes.util.find_library("libeay32"))
    else:
        openssl_paths.append(ctypes.util.find_library("ssl"))

    return openssl_paths


def discover_library():
    for path in discover_paths():
        try:
            return ctypes.CDLL(path)
        except OSError:
            pass
    raise OSError("OpenSSL is unavailable")
