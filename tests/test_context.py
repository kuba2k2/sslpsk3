#  Copyright (c) Kuba Szczodrzyński 2025-9-2.

import sys
from socket import socket
from ssl import (
    CERT_NONE,
    PROTOCOL_TLS,
    PROTOCOL_TLS_CLIENT,
    PROTOCOL_TLS_SERVER,
    SSLContext,
    SSLSocket,
    TLSVersion,
)

import pytest
from base import PROTOCOLS, TestBase

from sslpsk3 import SSLPSKContext

if sys.version_info >= (3, 13, 0):
    # On Python 3.13 the built-in implementation is used - also test the custom one
    FORCE_OPENSSL = [False, True]
    SSL_CONTEXT = [SSLPSKContext, SSLContext]
else:
    FORCE_OPENSSL = [False]
    SSL_CONTEXT = [SSLPSKContext]


@pytest.mark.parametrize("protocol", PROTOCOLS)
@pytest.mark.parametrize("force_openssl", FORCE_OPENSSL)
@pytest.mark.parametrize("ssl_context", SSL_CONTEXT)
@pytest.mark.parametrize("with_identity", [False, True])
class TestContext(TestBase):

    @pytest.fixture(scope="function", autouse=True)
    def setup(self, protocol, force_openssl, ssl_context, with_identity):
        self.protocol = protocol
        self.force_openssl = force_openssl
        self.ssl_context = ssl_context
        self.with_identity = with_identity

    def wrap_server(self, sock: socket) -> SSLSocket:
        context = self.ssl_context(protocol=self.protocol or PROTOCOL_TLS_SERVER)
        context.options = CERT_NONE
        context.set_ciphers(self.ciphers)
        context.check_hostname = False

        context.set_psk_server_callback(
            callback=lambda identity: (
                self.psk if not self.with_identity or identity == self.identity else b""
            ),
            identity_hint=self.hint,
        )

        return context.wrap_socket(
            sock=sock,
            server_side=True,
        )

    def wrap_client(self, sock: socket) -> SSLSocket:
        context = self.ssl_context(protocol=self.protocol or PROTOCOL_TLS_CLIENT)
        context.options = CERT_NONE
        context.set_ciphers(self.ciphers)
        context.check_hostname = False

        context.set_psk_client_callback(
            callback=lambda hint: (
                self.with_identity and self.identity or b"",
                self.psk,
            ),
        )

        if self.protocol in [PROTOCOL_TLS, None] and not self.with_identity:
            # TLSv1.3 requires a client identity
            # Use at most TLSv1.2 if not passing client identity
            # This is only required in the client socket; the server will adapt its version
            context.maximum_version = TLSVersion.TLSv1_2

        return context.wrap_socket(
            sock=sock,
            server_side=False,
        )


del TestBase
