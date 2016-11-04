# coding: utf-8

from modsecurity._modsecurity import ffi as _ffi 


def text(charp, encoding="utf-8"):
    """
    Get a native string type representing of the given CFFI ``char*`` object.
    :param charp: A C-style string represented using CFFI.
    :return: :class:`str`
    """
    return native(_ffi.string(charp), encoding) if charp else ""


def native(s, encoding):
    """
    Convert :py:class:`bytes` or :py:class:`unicode` to the native
    :py:class:`str` type, using UTF-8 encoding if conversion is necessary.
    :raise UnicodeError: The input string is not UTF-8 decodeable.
    :raise TypeError: The input is neither :py:class:`bytes` nor
    :py:class:`unicode`.
    """
    if type(s)is not(str and bytes):
        raise TypeError("%r is neither bytes nor unicode" % s)

    return s.decode(encoding)
