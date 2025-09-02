#  Copyright (c) Kuba Szczodrzyński 2025-9-2.

from socket import socket
from ssl import (
    CERT_NONE,
    PROTOCOL_TLS_CLIENT,
    PROTOCOL_TLS_SERVER,
    SSLSocket,
    TLSVersion,
)

from base import TestBase

from sslpsk3 import SSLPSKContext


class TestContextSimple(TestBase):

    def wrap_server(self, sock: socket) -> SSLSocket:
        context = SSLPSKContext(protocol=PROTOCOL_TLS_SERVER)
        context.maximum_version = TLSVersion.TLSv1_2
        context.set_ciphers(self.ciphers)

        context.set_psk_server_callback(
            callback=lambda identity: self.psk,
            identity_hint=self.hint,
        )

        return context.wrap_socket(
            sock=sock,
            server_side=True,
        )

    def wrap_client(self, sock: socket) -> SSLSocket:
        context = SSLPSKContext(protocol=PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = CERT_NONE
        context.maximum_version = TLSVersion.TLSv1_2
        context.set_ciphers(self.ciphers)

        context.set_psk_client_callback(
            callback=lambda hint: (self.identity, self.psk),
        )

        return context.wrap_socket(
            sock=sock,
            server_side=False,
        )


del TestBase
