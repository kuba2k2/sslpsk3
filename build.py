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

extension = Extension(
    "sslpsk3._sslpsk3",
    sources=["sslpsk3/_sslpsk3.c"],
    libraries=LIB_NAMES,
    include_dirs=["openssl/include/"],
    library_dirs=["openssl/lib/VC/"],
)


def build(setup_kwargs):
    setup_kwargs.update(
        dict(
            ext_modules=[extension],
        ),
    )
