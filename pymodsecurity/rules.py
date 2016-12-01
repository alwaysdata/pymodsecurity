# -*- coding: utf-8 -*-
"""
pymodsecurity.rules
-------------------

Provide a class :class:`Rules` gathering methods coming from
libmodsecurity.
"""

from pymodsecurity import utils
from pymodsecurity._modsecurity import ffi as _ffi
from pymodsecurity._modsecurity import lib as _lib
from pymodsecurity.exceptions import InternalError


_NULL = _ffi.NULL


class Rules:
    """
    Wrapper for C function built from **rules.h** via CFFI.
    """
    def __init__(self,):
        _rules_set = _lib.msc_create_rules_set()
        assert _rules_set != _NULL
        self._rules_set = _ffi.gc(_rules_set, _lib.msc_rules_cleanup)

        self._error_pointer = _ffi.new("const char **", _NULL)

    def _last_error_message(self):
        """
        Retrieve error string pointed by error_pointer.
        This string is issued by libmodsecurity.
        """
        error_message = utils.text(self._error_pointer[0])
        if not error_message:
            error_message = "No information provided by libmodsecurity"
        self._error_pointer[0] = _NULL

        return error_message

    def dump_rules(self):
        """
        Print rules IDs and addresses sorted by rule phase to stdout.
        """
        _lib.msc_rules_dump(self._rules_set)

    def merge_rules(self, other_rules):
        """
        Merge a rules set into another one.

        :param other_rules: an instance of :class:`Rules`

        :return: number of rules merged
        """
        return _lib.msc_rules_merge(self._rules_set,
                                    other_rules._rules_set)

    def add_rules_remote(self, key, uri):
        """
        Fetch rules over a network and merge it with the current rules set.

        :param key: key as :class:`str`
        :param uri: URI address

        :return: number of rules merged as :class:`int`
        """
        retvalue = _lib.msc_rules_add_remote(self._rules_set,
                                             key.encode(),
                                             uri.encode(),
                                             self._error_pointer)
        if retvalue == -1:
            raise InternalError(self._last_error_message())
        return retvalue

    def add_rules_file(self, filename):
        """
        Add rules stored in a file and merge it with the current rules set.

        :param filename: file path to rules file

        :return: number of rules merged as :class:`int`
        """
        retvalue = _lib.msc_rules_add_file(self._rules_set,
                                           filename.encode(),
                                           self._error_pointer)
        if retvalue == -1:
            raise InternalError(self._last_error_message())
        return retvalue

    def add_rules(self, plain_rules):
        """
        Add custom rule defined by ``plain rules`` and merge it with the
        current rules set.

        :param plain_rules: ModSecurity rule(s) as :class:`str`

        :return: number of rules merged as :class:`int`
        """
        retvalue = _lib.msc_rules_add(self._rules_set,
                                      plain_rules.encode(),
                                      self._error_pointer)
        if retvalue == -1:
            raise InternalError(self._last_error_message())
        return retvalue
