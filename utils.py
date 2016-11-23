# -*- coding: utf-8 -*-

from pymodsecurity._modsecurity import ffi as _ffi


def text(charp):
    """
    Get a native string type representing of the given CFFI ``char *`` object.

    :param charp: C-style string represented using CFFI.
    :return: a :class:`str`
    """
    return bytes.decode(_ffi.string(charp)) if charp else ""
