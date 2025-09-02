# sslpsk3

[![PyPI version](https://badge.fury.io/py/sslpsk3.svg)](https://badge.fury.io/py/sslpsk3)

This module adds TLS-PSK support to the `ssl` package in Python 3.7+.

## Installation

```pip install sslpsk3```

`pip` builds from source for Linux and Mac OSX, so a C compiler, the Python
development headers, and the OpenSSL development headers are required. For
Microsoft Windows, pre-built binaries are available so there are no such
prerequisites.

## Usage

The old method of using `ssl.wrap_socket(...)` is deprecated and not available in Python 3.12+, so the recommended way
is `SSLContext`.

This library introduces a drop-in replacement `SSLPSKContext` class which supports TLS-PSK.

On Python 3.13 and newer, it uses the native implementation; on older versions, a custom implementation based on OpenSSL
is used.

Server code example:

```py
import ssl
from sslpsk3 import SSLPSKContext

context = SSLPSKContext(ssl.PROTOCOL_TLS_SERVER)
context.maximum_version = ssl.TLSVersion.TLSv1_2
context.set_ciphers("PSK")
context.set_psk_server_callback(lambda identity: b"abcdef", identity_hint="server_hint")
sock = context.wrap_socket(...)
```

Client code example:

```py
import ssl
from sslpsk3 import SSLPSKContext

context = SSLPSKContext(ssl.PROTOCOL_TLS_CLIENT)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
context.maximum_version = ssl.TLSVersion.TLSv1_2
context.set_ciphers("PSK")
context.set_psk_client_callback(lambda hint: ("client_identity", b"abcdef"))
sock = context.wrap_socket(...)
```

For more information refer
to [the Python documentation](https://docs.python.org/3.13/library/ssl.html#ssl.SSLContext.set_psk_client_callback) as
well as [the `test_context_simple.py` test file](tests/test_context_simple.py).

That being said, this library also still contains a backported version of `wrap_context()`, which works the same way as
in previous versions of `sslpsk`/`sslpsk2`/`sslpsk3`. If possible, please migrate to `SSLPSKContext` anyway.

## Backstory

There were two published versions on PyPI, both without Python 3.11 support.

Additionally, for whatever reason, the Windows build of `sslpsk2` for Python 3.10 has been linked against OpenSSL 3,
while Python 3.10 on Windows uses OpenSSL 1.1.1, which causes run-time crashes (Python started using OpenSSL 3 in
3.11.5).

This fork aims to fix the incompatibility between Python and OpenSSL versions.

Availability of binary wheels for Windows:

|             | `sslpsk` | `sslpsk2` | `sslpsk3` |
|-------------|----------|-----------|-----------|
| Python 2.7  | 1.0.0    | -         | -         |
| Python 3.3  | 1.0.0    | -         | -         |
| Python 3.4  | 1.0.0    | -         | -         |
| Python 3.5  | 1.0.0    | -         | -         |
| Python 3.6  | 1.0.0    | -         | -         |
| Python 3.7  | -        | 1.0.1     | 2.0.0+    |
| Python 3.8  | -        | 1.0.1     | 1.1.0+    |
| Python 3.9  | -        | 1.0.1     | 1.1.0+    |
| Python 3.10 | -        | 1.0.2     | 1.1.0+    |
| Python 3.11 | -        | -         | 1.1.0+    |
| Python 3.12 | -        | -         | 2.0.0+    |
| Python 3.13 | -        | -         | 2.0.0+    |

## Changelog

+ 0.1.0 (July 31, 2017)
    + initial release
+ 1.0.0 (August 2, 2017)
    + include tests in pip distribution
    + add support for Windows
+ 1.0.1 (August 11, 2020)
    + OpenSSL 1.1.1
    + Fix with _sslobj
    + Build from source in Windows with error description, when OpenSSL files are not present
+ 1.1.0 (September 13, 2023)
    + Migrate to GitHub actions
    + Reformat code
    + Support OpenSSL v1 and v3
+ 2.0.0 (September 2, 2025)
    + Rewrite library based on SSLContext
    + Support Python 3.13 and later
    + Add a new test suite

## Acknowledgments

Fork of [drbild/sslpsk](https://github.com/drbild/sslpsk).

The main approach was borrowed from
[webgravel/common-ssl](https://github.com/webgravel/common-ssl).

Version from [autinerd/sslpsk2](https://github.com/autinerd/sslpsk2) updated to work with OpenSSL v1 and v3.

Updates for `SSLContext` inspired by a [PR created by @doronz88](https://github.com/drbild/sslpsk/pull/28).

## Contributing

Please submit bugs, questions, suggestions, or (ideally) contributions as
issues and pull requests on GitHub.

## License

Copyright 2017 David R. Bild, 2020 Sidney Kuyateh, 2025 Kuba Szczodrzyński

Licensed under the Apache License, Version 2.0 (the "License"); you may not
use this work except in compliance with the License. You may obtain a copy of
the License from the LICENSE.txt file or at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations under
the License.
