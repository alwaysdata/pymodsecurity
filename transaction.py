#! python3
# coding: utf-8

import os

import modsecurity.utils as utils
from modsecurity._modsecurity import ffi as _ffi
from modsecurity._modsecurity import lib as _lib
from modsecurity.exceptions import ProcessConnectionError
from modsecurity.exceptions import FeedingError
from modsecurity.exceptions import EmptyBodyError
from modsecurity.exceptions import BodyNotUpdated
from modsecurity.exceptions import LoggingActionError

NULL = _ffi.NULL


class Transaction:
    """
    Wrapper for C function built from transaction.h via CFFI.
    """
    def __init__(self, ModSecurity, Rules):
        self.null = NULL
        if ModSecurity and Rules:  # prefer use of `assert` ?
            self._modsecurity = ModSecurity._modsecurity_struct
            self._rules = Rules._rules_set
            self._log_callback = NULL  # _log_callback has to be properly defined if needed (maybe fetch it from modsecurity.py ?)
            _charp = _ffi.new("char *")
            self._intervention = _ffi.new("ModSecurityIntervention *",
                                          [0, 0, _charp, _charp, 0])

            _transaction_struct = _lib.msc_new_transaction(self._modsecurity,
                                                           self._rules,
                                                           self._log_callback)
            assert(_transaction_struct != NULL)
            self._transaction_struct = _ffi.gc(_transaction_struct,
                                               _lib.msc_transaction_cleanup)

    def check_cffi_return_value(self,
                                returned_value,
                                error_value_expected,
                                error_to_raise):
        """
        Maybe a futur feature which simply checks the returning value
        obtained by a call to cffi lib.
        """
        if returned_value == error_value_expected:
            raise error_to_raise

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
        client_ip = utils.encode_string(client_ip)
        server_ip = utils.encode_string(server_ip)

        retvalue = _lib.msc_process_connection(self._transaction_struct,
                                               client_ip,
                                               client_port,
                                               server_ip,
                                               server_port)
        if not retvalue:
            raise ProcessConnectionError.failed_at("connection")

        self.has_intervention(self._intervention)

    def process_uri(self, uri, method, http_version):
        """
        Perform the analysis on the URI and all the query
        string variables.

        This function should be called at very beginning
        of a request process, it is expected to be executed
        prior to the virtual host resolution, when the
        connection arrives on the server.
        """
        if (method == 'GET' or method == 'POST' or method == 'PUT'):
            method = utils.encode_string(method)
        else:
            message = "Bad HTTP method : " + method
            raise ValueError(message)

        if (http_version == '1.0'
                or http_version == '1.1'
                or http_version == '2.0'):
            http_version = utils.encode_string(http_version)
        else:
            message = "Bad HTTP version : " + http_version
            raise ValueError(message)

        uri = utils.encode_string(uri)
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

        self.has_intervention(self._intervention)

    def add_request_header(self, key, value):
        """
        Adds a request header.

        With this function it is possible to feed ModSecurity
        with a request header.

        This function expects a NULL terminated string,
        for both: key and value.
        """
        key = utils.encode_string(key)
        value = utils.encode_string(value)

        retvalue = _lib.msc_add_request_header(self._transaction_struct,
                                               key,
                                               value)
        if not retvalue:
            raise FeedingError.failed_at("request header")

    def add_n_request_header(self, key, value):
        """
        Adds a request header.

        Same as msc_add_request_header, do not expect a NULL
        terminated string, instead it expect the string and
        the string size, for the value and key.
        """
        key_size = len(key)
        value_size = len(value)
        key = utils.encode_string(key)
        value = utils.encode_string(value)

        retvalue = _lib.msc_add_n_request_header(self._transaction_struct,
                                                 key,
                                                 key_size,
                                                 value,
                                                 value_size)
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

        A third option should be developed which is
        share your application buffer. In any case,
        remember that the utilization of this function
        may reduce your server throughput, as this buffer
        creations is computationally expensive.

        While feeding ModSecurity remember to keep checking
        if there is an intervention, Sec Language has
        the capability to set the maximum inspection size
        which may be reached, and the decision on what to do
        in this case is upon the rules.
        """
        size = len(body)
        if size:
            body = utils.encode_string(body)
            retvalue = _lib.msc_append_request_body(self._transaction_struct,
                                                    body,
                                                    size)
            if not retvalue:
                raise FeedingError.failed_at("request body")
        else:
            raise EmptyBodyError

    def get_request_body_from_file(self, filepath):
        if not os.path.isfile(filepath):
            raise FileNotFoundError

        filepath = utils.encode_string(filepath)

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

        self.has_intervention(self._intervention)

    def process_response_headers(self, statuscode, protocol):
        """
        Perform the analysis on the response headers.

        This function perform the analysis on the response
        headers, notice however that the headers should be
        added prior to the execution of this function.

        Remember to check for a possible intervention.
        """
        protocol = utils.encode_string(protocol)

        retvalue = _lib.msc_process_response_headers(self._transaction_struct,
                                                     statuscode,
                                                     protocol)
        if not retvalue:
            raise ProcessConnectionError.failed_at("response headers")

        self.has_intervention(self._intervention)

    def add_response_header(self, key, value):
        """
        Adds a response header

        With this function it is possible to feed
        ModSecurity with a responseheader.

        This function expects a NULL terminated string,
        for both: key and value.
        """
        key = utils.encode_string(key)
        value = utils.encode_string(value)

        retvalue = _lib.msc_add_response_header(self._transaction_struct,
                                                key,
                                                value)
        if not retvalue:
            raise FeedingError.failed_at("response header")

    def add_n_response_header(self, key, value):
        """
        Adds a response header

        Same as add_response_header, but do not expect a
        NULL terminated string, instead it expect the
        string and the string size, for the value and key.
        """
        key_size = len(key)
        value_size = len(value)
        key = utils.encode_string(key)
        value = utils.encode_string(value)

        retvalue = _lib.msc_add_n_response_header(self._transaction_struct,
                                                  key,
                                                  key_size,
                                                  value,
                                                  value_size)
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

        self.has_intervention(self._intervention)

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
        size = len(body)
        if size:
            body = utils.encode_string(body)
            retvalue = _lib.msc_append_request_body(self._transaction_struct,
                                                    body,
                                                    size)
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
        if retvalue == NULL:
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
        Logging all information relative to this transaction.

        At this point there is not need to hold the connection,
        the response can be delivered prior to the execution
        of this function.
        """
        retvalue = _lib.msc_process_logging(self._transaction_struct)
        if not retvalue:
            raise LoggingActionError
