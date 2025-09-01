# Copyright (c) Kuba Szczodrzyński 2023-09-12.

import platform
import sys

from setuptools.extension import Extension

if sys.platform == "win32" and platform.architecture()[0] == "64bit":
    LIB_NAMES = ["libssl64MD", "libcrypto64MD"]
elif sys.platform == "win32" and platform.architecture()[0] == "32bit":
    LIB_NAMES = ["libssl32MD", "libcrypto32MD"]
else:
    LIB_NAMES = ["ssl"]

extension_openssl1 = Extension(
    "sslpsk3._sslpsk3_openssl1",
    sources=["sslpsk3/_sslpsk3.c"],
    libraries=LIB_NAMES,
    include_dirs=["openssl1/include/"],
    library_dirs=["openssl1/lib/VC/"],
    define_macros=[
        ("OPENSSL_VER", "openssl1"),
        ("INIT_FUNC", "PyInit__sslpsk3_openssl1"),
    ],
)
extension_openssl3 = Extension(
    "sslpsk3._sslpsk3_openssl3",
    sources=["sslpsk3/_sslpsk3.c"],
    libraries=LIB_NAMES,
    include_dirs=["openssl3/include/"],
    library_dirs=["openssl3/lib/VC/"],
    define_macros=[
        ("OPENSSL_VER", "openssl3"),
        ("INIT_FUNC", "PyInit__sslpsk3_openssl3"),
    ],
)


def build(setup_kwargs):
    setup_kwargs.update(
        dict(
            ext_modules=[extension_openssl1, extension_openssl3],
        ),
    )
