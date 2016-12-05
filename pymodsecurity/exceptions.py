# -*- coding: utf-8 -*-
"""
pymodsecurity.exceptions
------------------------
"""


class Error(Exception):
    """
    Base class for ModSecurity exception used by
    :class:`~pymodsecurity.modsecurity`, :class:`~pymodsecurity.transaction`
    and :class:`~pymodsecurity.rules` modules.
    """
    default_message = None

    def __init__(self, message=None, *pargs, **kargs):
        if not message:
            message = self.default_message

        super().__init__(message, *pargs, **kargs)


class InternalError(Error):
    """
    Error raised when libmodsecurity has fed an error pointer.
    """


class ProcessConnectionError(Error):
    """
    Error raised when the C interface fails to perfom the analysis on the
    connection.
    """
    default_message = "Failed to perform connection analysis"

    @classmethod
    def failed_at(cls, where):
        return cls(cls.default_message + " on " + where)


class FeedingError(ProcessConnectionError):
    """
    Error raised when the C interface fails to feed ModSecurity with datas
    (e.g. request headers)
    """
    default_message = "Failed to feed ModSecurity"


class LoggingActionError(Error):
    """
    Error raised when the C interface fails to log all information realtive to
    a transaction.
    """
    default_message = "Failed to log information about the transaction"
