# -*- coding: utf-8 -*-

import sys

from pymodsecurity._modsecurity import ffi as _ffi

_encoding = sys.getdefaultencoding()


def as_bytes(arg, encoding=_encoding):
    try:
        return bytes(arg, encoding)
    except TypeError:
        # ``arg`` is not a :class:`str`
        return arg


def text(charp):
    """
    Get a native string type representing of the given CFFI ``char *`` object.

    :param charp: C-style string represented using CFFI.
    :return: a :class:`str`
    """
    return bytes.decode(_ffi.string(charp)) if charp else ""
