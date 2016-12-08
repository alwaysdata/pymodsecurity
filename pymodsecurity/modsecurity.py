# -*- coding: utf-8 -*-
"""
pymodsecurity.modsecurity
--------------------------

Provide a class :class:`ModSecurity` gathering methods coming from
libmodsecurity.
"""

import functools

from pymodsecurity._modsecurity import ffi as _ffi
from pymodsecurity._modsecurity import lib as _lib
from pymodsecurity import utils

_NULL = _ffi.NULL


class ModSecurity:
    """
    Wrapper for C function built from **modsecurity.h** via CFFI.
    """
    def __init__(self,):
        _modsecurity_struct = _lib.msc_init()
        assert _modsecurity_struct != _NULL
        self._modsecurity_struct = _ffi.gc(_modsecurity_struct,
                                           _lib.msc_cleanup)

        self._log_callback = _NULL

    def set_log_callback(self, callback):
        """
        Set the log callback function.

        It is neccessary to indicate to ModSecurity which function within
        the connector should be called when logging is required.

        :param callback: Python callable object

        .. note:: The callback should perform few operations or even none on
            data.

        .. warning:: Be careful when writing the Python callback function. If
            it returns an object of the wrong type, or more generally raises
            an exception, the exception cannot be propagated. Instead, it is
            printed to stderr and the C-level callback is made to return a
            default value (see CFFI callbacks documentation for details).
        """
        @functools.wraps(callback)
        def wrapper(data, message):
            if data == _NULL:
                data = None
            else:
                data = _ffi.from_handle(data)

            return callback(data, utils.text(message))

        self._log_callback = _ffi.callback("void (*)(void *, const char *)",
                                           wrapper)
        _lib.msc_set_log_cb(self._modsecurity_struct,
                            self._log_callback)

    def who_am_i(self):
        """
        Return information about this ModSecurity version and platform.

        Platform and version are two questions that community will ask prior
        to provide support. Making it available internally and to the
        connector as well.

        :return: ModSecurity version and platform.
        """
        retvalue = _lib.msc_who_am_i(self._modsecurity_struct)
        return utils.text(retvalue)

    def set_connector_info(self, connector):
        """
        Set information about the connector using the library.

        For the purpose of log it is necessary for ModSecurity to understand
        which ``connector`` is consuming the API.

        It is strongly recommended to set a information in the following
        pattern : *ConnectorName vX.Y.Z-tag (something else)*

        :param connector: information about the connector as :class:`str`
        """
        return _lib.msc_set_connector_info(self._modsecurity_struct,
                                           utils.as_bytes(connector))
