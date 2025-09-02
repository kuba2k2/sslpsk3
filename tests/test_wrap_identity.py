#  Copyright (c) Kuba Szczodrzyński 2025-9-1.

from socket import socket
from ssl import (
    PROTOCOL_TLS_CLIENT,
    PROTOCOL_TLS_SERVER,
    SSLSocket,
)

import pytest
from base import PROTOCOLS_AUTO, TestBase

from sslpsk3 import wrap_socket


@pytest.mark.parametrize("protocol", PROTOCOLS_AUTO)
class TestWrapIdentity(TestBase):

    @pytest.fixture(scope="function", autouse=True)
    def setup(self, protocol):
        self.protocol = protocol

    def wrap_server(self, sock: socket) -> SSLSocket:
        return wrap_socket(
            sock,
            psk=self.psk,
            hint=self.hint.encode(),
            ciphers=self.ciphers,
            ssl_version=self.protocol or PROTOCOL_TLS_SERVER,
            server_side=True,
        )

    def wrap_client(self, sock: socket) -> SSLSocket:
        return wrap_socket(
            sock,
            psk=(self.psk, self.identity.encode()),
            ciphers=self.ciphers,
            ssl_version=self.protocol or PROTOCOL_TLS_CLIENT,
            server_side=False,
        )


del TestBase
