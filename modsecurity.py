# -*- coding: utf-8 -*-
"""
pymodsecurity.modsecurity
-----------------------

Provide a class :class:`ModSecurity` gathering methods coming from
libmodsecurity C interface via CFFI engine.
"""

import functools

from pymodsecurity._modsecurity import ffi as _ffi
from pymodsecurity._modsecurity import lib as _lib
from pymodsecurity import utils

NULL = _ffi.NULL


class ModSecurity:
    """
    Wrapper for C function built from modsecurity.h via CFFI.
    """
    def __init__(self,):
        _modsecurity_struct = _lib.msc_init()
        assert _modsecurity_struct != NULL
        self._modsecurity_struct = _ffi.gc(_modsecurity_struct,
                                           _lib.msc_cleanup)

        self._id = self.who_am_i()
        self._log_callback = NULL

    def set_log_callback(self, modsec, callback):
        """
        Set the log callback function.

        It is neccessary to indicate to libModSecurity which function within
        the connector should be called when logging is required.

        :note: This method is not usable yet.
        """
        @functools.wraps(callback)
        def wrapper(self, modsec):
            callback()
            return

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

        This information maybe will be used by a log parser. If you want to
        update it, make it in a fashion that won't break the existent parsers.
        (e.g. adding extra information _only_ to the end of the string)

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
        pattern :
            ConnectorName vX.Y.Z-tag (something else)

        :param connector: information about the connector as :class:`str`
        """
        return _lib.msc_set_connector_info(self._modsecurity_struct,
                                           connector.encode())
