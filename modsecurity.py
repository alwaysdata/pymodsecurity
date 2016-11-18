# -*- coding: utf-8 -*-
"""
modsecurity.modsecurity
-----------------------

Provide a class :class:`ModSecurity` gathering methods coming from
libmodsecurity C interface via CFFI engine.
"""

import functools

from modsecurity._modsecurity import ffi as _ffi
from modsecurity._modsecurity import lib as _lib
from modsecurity import utils

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
        self._log_callback = NULL  # Has to be replaced by appropriate type, see set_log_callback()
        #self.set_log_callback(self._modsecurity_struct, self.log_cb_test())  # DEBUG

    def log_cb_test(self, *pargs):  # DEBUG
        """
        Test log callback function. This function has to be passed
        as input of set_log_callback in ordrer to be interfaced
        with libmodsecurity
        """
        pass

    def set_log_callback(self, modsec, callback):
        """
        Set the log callback function.

        It is neccessary to indicate to libModSecurity whichc function within
        the connector should be called when logging is required.
        """
        @functools.wraps(callback)
        def wrapper(self, modsec):  # an additionnal arg should probably go there
            callback()
            return  # something?

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

        For the purpose of log it is necessary for modsecurity to understand
        which ``connector`` is consuming the API.

        It is strongly recommended to set a information in the following
        pattern :
            ConnectorName vX.Y.Z-tag (something else)

        :param connector: information about the connector as :class:`str`
        """
        return _lib.msc_set_connector_info(self._modsecurity_struct,
                                           connector.encode())
