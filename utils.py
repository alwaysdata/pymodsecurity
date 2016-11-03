#! python3
# coding: utf-8

from modsecurity._modsecurity import ffi as _ffi 


def text(charp):
    """
    Get a native string type representing of the given CFFI ``char*`` object.
    :param charp: A C-style string represented using CFFI.
    :return: :class:`str`
    """
    if not charp:
        return ""

    return native(_ffi.string(charp))


def native(s):
    """
    Convert :py:class:`bytes` or :py:class:`unicode` to the native
    :py:class:`str` type, using UTF-8 encoding if conversion is necessary.
    :raise UnicodeError: The input string is not UTF-8 decodeable.
    :raise TypeError: The input is neither :py:class:`bytes` nor
        :py:class:`unicode`.
    """
    if type(s)is not(str and bytes):
        raise TypeError("%r is neither bytes nor unicode" % s)
    elif type(s) is bytes:
        return s.decode("utf-8")
    elif type(s) is str:
        return s.encode("utf-8")
    return s
