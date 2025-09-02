#  Copyright (c) Kuba Szczodrzyński 2025-9-2.

from socket import socket
from ssl import (
    CERT_NONE,
    SSLSocket,
)

import pytest
from base import PROTOCOLS_v1_2, TestBase

from sslpsk3 import SSLPSKContext


@pytest.mark.parametrize("protocol", PROTOCOLS_v1_2)
class TestContextSimple(TestBase):

    @pytest.fixture(scope="function", autouse=True)
    def setup(self, protocol):
        self.protocol = protocol

    def wrap_server(self, sock: socket) -> SSLSocket:
        context = SSLPSKContext(protocol=self.protocol)
        context.options = CERT_NONE
        context.set_ciphers(self.ciphers)
        context.check_hostname = False

        context.set_psk_server_callback(
            callback=lambda identity: self.psk,
            identity_hint=self.hint,
        )

        return context.wrap_socket(
            sock=sock,
            server_side=True,
        )

    def wrap_client(self, sock: socket) -> SSLSocket:
        context = SSLPSKContext(protocol=self.protocol)
        context.options = CERT_NONE
        context.set_ciphers(self.ciphers)
        context.check_hostname = False

        context.set_psk_client_callback(
            callback=lambda hint: (self.identity, self.psk),
        )

        return context.wrap_socket(
            sock=sock,
            server_side=False,
        )


del TestBase
