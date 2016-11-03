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
    # Another might append: the file has been opened 
    # but the rules merge() failed returning -1
    #
    # Simply raise an IOError ?


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


class ProcessConnectionError(ModSecurityException):
    """
    Error raised when the C interface fails to perfom
    the analysis on the connection.
    """
    default_message = "Failed to perform connection analysis"
    # Maybe it'd be useful to mention the fail location
    # e.g. "Failed on (request|response (header|body))"


class LoggingActionError(ModSecurityException):
    """
    Error raised when the C interface fails to log
    all information realtive to a transaction.
    """
    default_message = "Fail to log information about the transaction"
