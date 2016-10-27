#! python3
# coding: utf-8


class ModSecurityException(Exception):
    """
    Base class for ModSecurity exception used by modsecurity,
    transaction and  rules modules.
    """
    default_message = None

    def __init__(self, message=None, *pargs, **kargs):
        if not message:
            message = self.default_message

        super().__init__(message, *pargs, **kargs)


class InputError(ModSecurityException):
    """
    Input argument has not the right type.
    """
    default_message = "Bad input type"


class FileOpeningError(ModSecurityException):
    """
    Error raised when the C interface fails to open a file
    """
    default_message = "File cannot be opened"


class FetchRemoteFileError(ModSecurityException):
    """
    Error raised when the C interface fails to fetch a remote file
    """
    default_message = "Remote file cannot be fetched"


class RuleWrittingError(ModSecurityException):
    """
    Error raised when the C interface fails to add rules
    to current rules instance
    """
    default_message = "Rule(s) cannot be written"
