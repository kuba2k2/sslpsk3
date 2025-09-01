/* Copyright 2017 David R. Bild
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <openssl/ssl.h>

/* Copy PySSLObject/PySSLSocket from _ssl.c to expose the SSL*. */
#if !defined(PY_MAJOR_VERSION) || (PY_VERSION_HEX < 0x03000000)
#error Only Python 3.0 and later are supported
#endif

#define PY_VERSION_BETWEEN(start, end) ((PY_VERSION_HEX >= start) && (PY_VERSION_HEX < end))

typedef struct {
	PyObject_HEAD PyObject *socket;
#if PY_VERSION_BETWEEN(0x03000000, 0x03020000)
	void *SSL_CTX;
#endif
	SSL *ssl;
	/* etc */
} PySSLSocket;

/*
 * Python function that returns the client psk and identity.
 *
 * (ssl_id, hint) => (psk, idenity)
 */
static PyObject *python_psk_client_callback;

/*
 * Python function that returns the server psk.
 *
 * (ssl_id, identity) => psk
 */
static PyObject *python_psk_server_callback;

/*
 * Returns the index for an SSL socket, used to identity the socket across the
 * C/Python interface.
 */
long ssl_id(SSL *ssl) {
	return (long)ssl;
}

/*
 * Called from Python to set python_psk_client_callback;
 */
static PyObject *sslpsk3_set_python_psk_client_callback(PyObject *self, PyObject *args) {
	PyObject *cb;
	if (!PyArg_ParseTuple(args, "O", &cb)) {
		return NULL;
	}
	Py_XINCREF(cb);
	Py_XDECREF(python_psk_client_callback);
	python_psk_client_callback = cb;

	Py_RETURN_NONE;
}

/*
 * Called from Python to set python_psk_server_callback;
 */
static PyObject *sslpsk3_set_python_psk_server_callback(PyObject *self, PyObject *args) {
	PyObject *cb;
	if (!PyArg_ParseTuple(args, "O", &cb)) {
		return NULL;
	}
	Py_XINCREF(cb);
	Py_XDECREF(python_psk_server_callback);
	python_psk_server_callback = cb;

	Py_RETURN_NONE;
}

/*
 * Client callback for openSSL. Delegates to python_psk_client_callback.
 */
static unsigned int sslpsk3_psk_client_callback(
	SSL *ssl,
	const char *hint,
	char *identity,
	unsigned int max_identity_len,
	unsigned char *psk,
	unsigned int max_psk_len
) {
	int ret = 0;

	PyGILState_STATE gstate;

	PyObject *result;

	const char *psk_;
	const char *identity_;

	Py_ssize_t psk_len_;
	Py_ssize_t identity_len_;

	gstate = PyGILState_Ensure();

	if (python_psk_client_callback == NULL) {
		goto release;
	}

	// Call python callback
	result = PyObject_CallFunction(python_psk_client_callback, "ls", ssl_id(ssl), hint);
	if (result == NULL) {
		goto release;
	}

	// Parse result

	if (!PyArg_Parse(result, "(s#y#)", &identity_, &identity_len_, &psk_, &psk_len_)) {
		goto decref;
	}

	// Copy to caller
	if (psk_len_ > max_psk_len) {
		goto decref;
	}
	memcpy(psk, psk_, psk_len_);

	if (identity_len_ + 1 > max_identity_len) {
		goto decref;
	}
	memcpy(identity, identity_, identity_len_);
	identity[identity_len_] = 0;

	ret = psk_len_;

decref:
	Py_DECREF(result);

release:
	PyGILState_Release(gstate);

	return ret;
}

/*
 * Server callback for openSSL. Delegates to python_psk_server_callback.
 */
static unsigned int sslpsk3_psk_server_callback(
	SSL *ssl,
	const char *identity,
	unsigned char *psk,
	unsigned int max_psk_len
) {
	int ret = 0;

	PyGILState_STATE gstate;

	PyObject *result;

	const char *psk_;
	Py_ssize_t psk_len_;

	gstate = PyGILState_Ensure();

	if (python_psk_server_callback == NULL) {
		goto release;
	}

	// Call python callback
	result = PyObject_CallFunction(python_psk_server_callback, "ls", ssl_id(ssl), identity);
	if (result == NULL) {
		goto release;
	}

	// Parse result
	if (!PyArg_Parse(result, "y#", &psk_, &psk_len_)) {
		goto decref;
	}

	// Copy to caller
	if (psk_len_ > max_psk_len) {
		goto decref;
	}
	memcpy(psk, psk_, psk_len_);

	ret = psk_len_;

decref:
	Py_DECREF(result);

release:
	PyGILState_Release(gstate);

	return ret;
}

/*
 * Called from Python to set the client psk callback.
 */
static PyObject *sslpsk3_set_psk_client_callback(PyObject *self, PyObject *args) {
	PyObject *socket;
	SSL *ssl;

	if (!PyArg_ParseTuple(args, "O", &socket)) {
		return NULL;
	}

	ssl = ((PySSLSocket *)socket)->ssl;
	SSL_set_psk_client_callback(ssl, sslpsk3_psk_client_callback);

	return Py_BuildValue("l", ssl_id(ssl));
}

/*
 * Called from Python to set the server psk callback.
 */
static PyObject *sslpsk3_set_psk_server_callback(PyObject *self, PyObject *args) {
	PyObject *socket;
	SSL *ssl;

	if (!PyArg_ParseTuple(args, "O", &socket)) {
		return NULL;
	}

	ssl = ((PySSLSocket *)socket)->ssl;
	SSL_set_psk_server_callback(ssl, sslpsk3_psk_server_callback);

	return Py_BuildValue("l", ssl_id(ssl));
}

/*
 * Called from Python to set the server identity hint.
 */
static PyObject *sslpsk3_use_psk_identity_hint(PyObject *self, PyObject *args) {
	PyObject *socket;
	const char *hint;
	SSL *ssl;

	if (!PyArg_ParseTuple(args, "Os", &socket, &hint)) {
		return NULL;
	}

	ssl = ((PySSLSocket *)socket)->ssl;
	SSL_use_psk_identity_hint(ssl, hint);

	return Py_BuildValue("l", ssl_id(ssl));
}

/*
 * Called from Python to place the socket into server mode
 */
static PyObject *sslpsk3_set_accept_state(PyObject *self, PyObject *args) {
	PyObject *socket;
	SSL *ssl;

	if (!PyArg_ParseTuple(args, "O", &socket)) {
		return NULL;
	}

	ssl = ((PySSLSocket *)socket)->ssl;
	SSL_set_accept_state(ssl);

	return Py_BuildValue("l", ssl_id(ssl));
}

static PyMethodDef sslpsk3_methods[] = {
	{"sslpsk3_set_python_psk_client_callback", sslpsk3_set_python_psk_client_callback, METH_VARARGS, ""  },
	{"sslpsk3_set_python_psk_server_callback", sslpsk3_set_python_psk_server_callback, METH_VARARGS, ""  },
	{"sslpsk3_set_psk_client_callback",		sslpsk3_set_psk_client_callback,		 METH_VARARGS, ""	 },
	{"sslpsk3_set_psk_server_callback",		sslpsk3_set_psk_server_callback,		 METH_VARARGS, ""	 },
	{"sslpsk3_use_psk_identity_hint",		  sslpsk3_use_psk_identity_hint,			 METH_VARARGS, ""	 },
	{"sslpsk3_set_accept_state",				 sslpsk3_set_accept_state,			   METH_VARARGS, ""  },
	{NULL,									 NULL,								   0,			NULL}
};

#define STRINGIFY(x)	   #x
#define STRINGIFY_MACRO(x) STRINGIFY(x)

static struct PyModuleDef sslpsk3_moduledef = {
	PyModuleDef_HEAD_INIT,
	"sslpsk3_" STRINGIFY_MACRO(OPENSSL_VER),
	NULL,
	0,
	sslpsk3_methods,
	NULL,
	NULL,
	NULL,
	NULL,
};

PyMODINIT_FUNC INIT_FUNC(void) {
	PyObject *m = PyModule_Create(&sslpsk3_moduledef);
	return m;
}
