# coding: utf-8

from modsecurity._modsecurity import ffi as _ffi


def text(charp):
    """
    Get a native string type representing of the given CFFI ``char*`` object.
    :param charp: A C-style string represented using CFFI.
    :return: :class:`str`
    """
    return bytes.decode(_ffi.string(charp)) if charp else ""
