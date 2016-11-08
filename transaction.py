# coding: utf-8

import os

from modsecurity import utils
from modsecurity._modsecurity import ffi as _ffi
from modsecurity._modsecurity import lib as _lib
from modsecurity.exceptions import (ProcessConnectionError,
                                    FeedingError,
                                    BodyNotUpdated,
                                    LoggingActionError)


_NULL = _ffi.NULL


class Transaction:
    """
    Wrapper for C function built from transaction.h via CFFI.
    """
    def __init__(self, modsecurity, rules):
        self._modsecurity = modsecurity
        self._rules = rules
        self._log_callback = _NULL  # _log_callback has to be properly defined if needed (maybe fetch it from modsecurity.py ?)
        _charp1 = _ffi.new("char *")
        _charp2 = _ffi.new("char *")
        self._intervention = _ffi.new("ModSecurityIntervention *",
                                      [0, 0, _charp1, _charp2, 0])

        _transaction_struct = _lib.msc_new_transaction(self._modsecurity._modsecurity_struct,
                                                       self._rules._rules_set,
                                                       self._log_callback)
        assert _transaction_struct != _NULL
        self._transaction_struct = _ffi.gc(_transaction_struct,
                                           _lib.msc_transaction_cleanup)

    def process_connection(self, client_ip, client_port,
                           server_ip, server_port):
        """
        Perform the analysis on the connection.

        This function should be called at very beginning of a request
        process, it is expected to be executed prior to the virtual
        host resolution, when the connection arrives on the server.

        Remember to check for a possible intervention.

        client_ip Client's IP address in text format.
        client_port Client's port
        server_ip Server's IP address in text format.
        server_port Server's port
        """
        client_ip = client_ip.encode()
        server_ip = server_ip.encode()

        retvalue = _lib.msc_process_connection(self._transaction_struct,
                                               client_ip,
                                               client_port,
                                               server_ip,
                                               server_port)
        if not retvalue:
            raise ProcessConnectionError.failed_at("connection")

    def process_uri(self, uri, method, http_version):
        """
        Perform the analysis on the URI and all the query
        string variables.

        This function should be called at very beginning
        of a request process, it is expected to be executed
        prior to the virtual host resolution, when the
        connection arrives on the server.

        `http_version` must be '1.0' or '1.1' or '2.0' since
        value consistency is not checked (same goes for `method`).
        """
        uri = uri.encode()
        method = method.upper().encode()
        http_version = http_version.encode()

        retvalue = _lib.msc_process_uri(self._transaction_struct,
                                        uri,
                                        method,
                                        http_version)
        if not retvalue:
            raise ProcessConnectionError.failed_at("uri")

    def process_request_headers(self):
        """
        Perform the analysis on the request readers.

        This function perform the analysis on the request headers,
        notice however that the headers should be added prior to
        the execution of this function.

        Remember to check for a possible intervention.
        """
        retvalue = _lib.msc_process_request_headers(self._transaction_struct)
        if not retvalue:
            raise ProcessConnectionError.failed_at("request headers")

    def add_request_header(self, key, value):
        """
        Adds a request header.

        With this function it is possible to feed ModSecurity
        with a request header.

        This function expects a NULL terminated string,
        for both: key and value.
        """
        key = key.encode()
        value = value.encode()

        retvalue = _lib.msc_add_request_header(self._transaction_struct,
                                               key,
                                               value)
        if not retvalue:
            raise FeedingError.failed_at("request header")

    def append_request_body(self, body):
        """
        Adds request body to be inspected.

        With this function it is possible to feed
        ModSecurity with data for inspection regarding
        the request body. There are two possibilities here:

        1 - Adds the buffer in a row;
        2 - Adds it in chunks;

        While feeding ModSecurity remember to keep checking
        if there is an intervention, Sec Language has
        the capability to set the maximum inspection size
        which may be reached, and the decision on what to do
        in this case is upon the rules.
        """
        if not body:
            return

        body = body.encode()
        retvalue = _lib.msc_append_request_body(self._transaction_struct,
                                                body,
                                                len(body))
        if not retvalue:
            raise FeedingError.failed_at("request body")

    def get_request_body_from_file(self, filepath):
        """
        """
        # david : file not found est géré par libmodsecurity dans rules.py
        # je ne comprends pas l'utilisation de _remote
        # il est nécessaire d'expliciter dans la doc une exception standard ?
        if not os.path.isfile(filepath):
            raise FileNotFoundError

        filepath = filepath.encode()

        retvalue = _lib.msc_request_body_from_file(self._transaction_struct,
                                                   filepath)
        if not retvalue:
            raise ProcessConnectionError.failed_at("getting request body from file")

    def process_request_body(self):
        """
        Perform the analysis on the request body (if any)

        This function perform the analysis on the request
        body. It is optional to call that function.
        If this API consumer already know that there isn't a
        body for inspect it is recommended to skip this step.

        It is necessary to append the request body prior
        to the execution of this function.

        Remember to check for a possible intervention.
        """
        retvalue = _lib.msc_process_request_body(self._transaction_struct)
        if not retvalue:
            raise ProcessConnectionError.failed_at("request body")

    def process_response_headers(self, statuscode, protocol):
        """
        Perform the analysis on the response headers.

        This function perform the analysis on the response
        headers, notice however that the headers should be
        added prior to the execution of this function.

        Remember to check for a possible intervention.
        """
        protocol = protocol.encode()

        retvalue = _lib.msc_process_response_headers(self._transaction_struct,
                                                     statuscode,
                                                     protocol)
        if not retvalue:
            raise ProcessConnectionError.failed_at("response headers")

    def add_response_header(self, key, value):
        """
        Adds a response header

        With this function it is possible to feed
        ModSecurity with a responseheader.

        This function expects a NULL terminated string,
        for both: key and value.
        """
        key = key.encode()
        value = value.encode()

        retvalue = _lib.msc_add_response_header(self._transaction_struct,
                                                key,
                                                value)
        if not retvalue:
            raise FeedingError.failed_at("response header")

    def process_response_body(self):
        """
        Perform the analysis on the response body (if any)

        This function perform the analysis on the response body.
        It is optional to call that function.
        If this API consumer already know that there isn't
        a body for inspect it is recommended to skip this step.

        It is necessary to append the response body prior
        to the execution of this function.

        Remember to check for a possible intervention.
        """
        retvalue = _lib.msc_process_response_body(self._transaction_struct)
        if not retvalue:
            raise ProcessConnectionError.failed_at("response body")

    def append_response_body(self, body):
        """
        Adds reponse body to be inspected.

        With this function it is possible to feed ModSecurity
        with data for inspection regarding the response body.
        ModSecurity can also update the contents of the
        response body, this is not quite ready yet
        on this version of the API.

        If the content is updated, the client cannot receive
        the content length header filled, at least not with
        the old values. Otherwise unexpected behavior may happens.
        """
        if not body:
            return

        body = body.encode()
        retvalue = _lib.msc_append_response_body(self._transaction_struct,
                                                 body,
                                                 len(body))
        if not retvalue:
            raise FeedingError.failed_at("response body")

    def get_response_body(self):
        """
        Retrieve a buffer with the updated response body.

        This function is needed to be called whenever
        ModSecurity update the contents of the response
        body, otherwise there is no need to call this function.
        """
        retvalue = _lib.msc_get_response_body(self._transaction_struct)
        if retvalue == _NULL:
            raise BodyNotUpdated

    def get_response_body_length(self):
        """
        Retrieve the length of the updated response body.

        This function returns the size of the update
        response body buffer, notice however, that most
        likely there isn't an update. Thus, this function
        will return 0.
        """
        body_size = _lib.msc_get_response_body_length(self._transaction_struct)
        if not body_size:
            raise BodyNotUpdated

        return body_size

    def has_intervention(self, intervention):
        """
        Check if ModSecurity has anything to ask to the server.

        Intervention can generate a log event and/or perform
        a disruptive action.

        return True if a disrupive action has (to be) performed
        """
        # martin [review]: je ferais une review quand ça existera, mais je 
        # pense que tu peux envisager de faire un
        # collections.namedtuple("Intervention") ou une classe Intervention.

        retvalue = _lib.msc_intervention(self._transaction_struct,
                                         intervention)
        # return retvalue
        if retvalue:
            # Have to find a better way to display intervention attributes
            # It would probably depend on the architecture of almodsecurity
            print("!INTERVENTION! Something should be done")  # DEBUG

        print("status =", intervention.status)  # DEBUG
        print("pause =", intervention.pause)  # DEBUG
        print("url =", utils.text(intervention.url))  # DEBUG
        print("log =", utils.text(intervention.log))  # DEBUG
        print("disruptive =", intervention.disruptive)  # DEBUG

    def process_logging(self):
        """
        Log all information relative to this transaction.

        At this point there is not need to hold the connection,
        the response can be delivered prior to the execution
        of this function.
        """
        retvalue = _lib.msc_process_logging(self._transaction_struct)
        if not retvalue:
            raise LoggingActionError
