# Copyright (c) Kuba Szczodrzyński 2025-9-1.
# Original work: Copyright 2017 David R. Bild
# SSLContext refactor inspired by the PR made by @doronz88

import sys
from ssl import (
    CERT_NONE,
    OPENSSL_VERSION_INFO,
    PROTOCOL_TLS,
    PROTOCOL_TLS_CLIENT,
    PROTOCOL_TLS_SERVER,
    SSLContext,
    SSLObject,
    SSLSocket,
)
from typing import Callable, Dict, Optional, Tuple, Union

from _ssl import _SSLSocket

if OPENSSL_VERSION_INFO >= (3, 0):
    from sslpsk3 import _sslpsk3_openssl3 as _sslpsk3
else:
    from sslpsk3 import _sslpsk3_openssl1 as _sslpsk3

Hint = Optional[str]
Identity = Optional[str]
Psk = bytes
ClientCallback = Callable[[Hint], Tuple[Identity, Psk]]
ServerCallback = Callable[[Identity], Psk]


# noinspection PyUnresolvedReferences,PyProtectedMember
def get_ssl_socket(sock: Union[SSLSocket, SSLObject]) -> _SSLSocket:
    if isinstance(sock._sslobj, _SSLSocket):
        return sock._sslobj
    return sock._sslobj._sslobj


class SSLPSKContext(SSLContext):
    psk_client_callback: Optional[ClientCallback] = None
    psk_server_callback: Optional[ServerCallback] = None
    psk_server_hint: Hint = None
    psk_force_openssl: bool = False

    def set_psk_client_callback(
        self,
        callback: Optional[ClientCallback],
    ) -> None:
        if sys.version_info >= (3, 13, 0) and not self.psk_force_openssl:
            super().set_psk_client_callback(callback)
            return
        self.psk_client_callback = callback

    def set_psk_server_callback(
        self,
        callback: Optional[ServerCallback],
        identity_hint: Hint = None,
    ) -> None:
        if sys.version_info >= (3, 13, 0) and not self.psk_force_openssl:
            super().set_psk_server_callback(callback, identity_hint)
            return
        self.psk_server_callback = callback
        self.psk_server_hint = identity_hint

    def setup_psk_callbacks(self, sock: Union[SSLSocket, SSLObject]) -> None:
        # this is a no-op on Python 3.13 and newer, since callbacks aren't set
        if self.psk_client_callback and not sock.server_side:
            ssl_id = _sslpsk3.sslpsk3_set_psk_client_callback(get_ssl_socket(sock))
            psk_contexts[ssl_id] = self
        if self.psk_server_callback and sock.server_side:
            hint = self.psk_server_hint or ""
            ssl_id = _sslpsk3.sslpsk3_set_accept_state(get_ssl_socket(sock))
            _sslpsk3.sslpsk3_set_psk_server_callback(get_ssl_socket(sock))
            _sslpsk3.sslpsk3_use_psk_identity_hint(get_ssl_socket(sock), hint)
            psk_contexts[ssl_id] = self


class SSLPSKObject(SSLObject):
    def do_handshake(self):
        # noinspection PyTypeChecker
        context: SSLPSKContext = self.context
        context.setup_psk_callbacks(self)
        super().do_handshake()


class SSLPSKSocket(SSLSocket):
    def do_handshake(self, *args, **kwargs):
        # noinspection PyTypeChecker
        context: SSLPSKContext = self.context
        context.setup_psk_callbacks(self)
        super().do_handshake(*args, **kwargs)


SSLPSKContext.sslobject_class = SSLPSKObject
SSLPSKContext.sslsocket_class = SSLPSKSocket
psk_contexts: Dict[int, SSLPSKContext] = {}


def openssl_psk_client_callback(
    ssl_id: int,
    hint: Hint,
) -> Tuple[Identity, Psk]:
    """
    :param ssl_id: SSL socket ID
    :param hint: server hint
    :return: (identity, psk) tuple
    """
    if ssl_id not in psk_contexts:
        return "", b""
    context = psk_contexts[ssl_id]
    if not context.psk_client_callback:
        return "", b""
    return context.psk_client_callback(hint or None)


def openssl_psk_server_callback(
    ssl_id: int,
    identity: Identity,
) -> Psk:
    """
    :param ssl_id: SSL socket ID
    :param identity: client identity
    :return: psk
    """
    if ssl_id not in psk_contexts:
        return b""
    context = psk_contexts[ssl_id]
    if not context.psk_server_callback:
        return b""
    return context.psk_server_callback(identity or None)


# give the C code access to Python methods that will retrieve the PSK
_sslpsk3.sslpsk3_set_python_psk_client_callback(openssl_psk_client_callback)
_sslpsk3.sslpsk3_set_python_psk_server_callback(openssl_psk_server_callback)


def _wrap_socket_client(
    context: SSLPSKContext,
    callback: Union[Psk, Tuple[Psk, bytes], Callable[[bytes], Tuple[Psk, bytes]]],
):
    def cb(hint: Hint) -> Tuple[Identity, Psk]:
        value = callback
        if callable(value):
            value = value(hint and hint.encode() or None)
        if isinstance(value, tuple):
            psk, identity = value
            return identity.decode(), psk
        else:
            return "", value

    context.set_psk_client_callback(callback=cb)


def _wrap_socket_server(
    context: SSLPSKContext,
    callback: Union[Psk, Callable[[bytes], Psk]],
    identity_hint: bytes,
):
    def cb(identity: Identity) -> Psk:
        if callable(callback):
            return callback(identity and identity.encode() or None)
        return callback

    context.set_psk_server_callback(
        callback=cb,
        identity_hint=identity_hint and identity_hint.decode(),
    )


def wrap_socket(
    sock,
    psk,
    hint=None,
    keyfile=None,
    certfile=None,
    server_side=False,
    cert_reqs=CERT_NONE,
    ssl_version=PROTOCOL_TLS,
    ca_certs=None,
    do_handshake_on_connect=True,
    suppress_ragged_eofs=True,
    ciphers=None,
) -> SSLSocket:
    """
    :param sock: socket to wrap
    :param psk: one of:
            1) PSK (bytes);
            2) client-side only: tuple of bytes (psk, identity|None);
            3) callable that returns 1) or 2), given the server_hint|None or client_identity|None as parameter (bytes)
    :param hint: server identity hint (bytes)
    :param keyfile: for SSLContext.load_cert_chain()
    :param certfile: for SSLContext.load_cert_chain()
    :param server_side: for SSLContext.wrap_socket()
    :param cert_reqs: for SSLContext.options
    :param ssl_version: for SSLContext()
    :param ca_certs: for SSLContext.load_verify_locations()
    :param do_handshake_on_connect: for SSLContext.wrap_socket()
    :param suppress_ragged_eofs: for SSLContext.wrap_socket()
    :param ciphers: for SSLContext.set_ciphers()
    :return: wrapped SSLSocket
    """

    context = SSLPSKContext(protocol=ssl_version)
    context.options = cert_reqs
    if keyfile and certfile:
        context.load_cert_chain(certfile, keyfile)
    if ca_certs:
        context.load_verify_locations(ca_certs)
    if ciphers:
        context.set_ciphers(ciphers)

    if psk and server_side:
        _wrap_socket_server(context, psk, hint)
    elif psk:
        _wrap_socket_client(context, psk)

    if psk and ssl_version in [PROTOCOL_TLS_CLIENT, PROTOCOL_TLS_SERVER]:
        context.check_hostname = False

    return context.wrap_socket(
        sock=sock,
        server_side=server_side,
        do_handshake_on_connect=do_handshake_on_connect,
        suppress_ragged_eofs=suppress_ragged_eofs,
    )
