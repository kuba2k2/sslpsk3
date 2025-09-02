#  Copyright (c) Kuba Szczodrzyński 2025-9-2.

import sys
from os import system
from pathlib import Path
from shutil import make_archive
from tempfile import TemporaryDirectory
from zipfile import ZipFile

# This script will patch any matching *.whl files in "dist/"
# to replace "libssl-3-x64.dll" dependency with the correct
# "libssl-3.dll" dependency (same for "libssl-1_1.dll").
# It will then run "pip" to install the wheels locally.
# Sorry, I don't know of any cleaner way to make this work...

FIND_OPENSSL1 = b"libssl-1_1-x64.dll"
REPL_OPENSSL1 = b"libssl-1_1.dll\x00\x00\x00\x00"
FIND_OPENSSL3 = b"libssl-3-x64.dll"
REPL_OPENSSL3 = b"libssl-3.dll\x00\x00\x00\x00"

dist_path = Path(__file__).with_name("dist").resolve()
version = f"cp{sys.version_info[0]}{sys.version_info[1]}"

for whl_path in dist_path.glob(f"sslpsk3-*-{version}-*.whl"):
    with TemporaryDirectory() as temp:
        temp_path = Path(temp).resolve()
        print(f"Processing {whl_path}:")

        zipfile = ZipFile(whl_path, "r")
        print(f" - extracting to {temp_path}")
        zipfile.extractall(temp_path)
        zipfile.close()

        for pyd_path in (temp_path / "sslpsk3").glob("*.pyd"):
            print(f" - patching {pyd_path}")
            data = pyd_path.read_bytes()
            data = data.replace(FIND_OPENSSL1, REPL_OPENSSL1)
            data = data.replace(FIND_OPENSSL3, REPL_OPENSSL3)
            pyd_path.write_bytes(data)

        print(f" - packing to {whl_path}")
        make_archive(str(whl_path), "zip", str(temp_path))
        whl_path.unlink()
        whl_path.with_suffix(".whl.zip").rename(whl_path)

        print(f" - installing {whl_path}")
        system(f"python -m pip install --force-reinstall {whl_path}")
