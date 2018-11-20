# -*- coding: utf-8 -*-
"""
pymodsecurity.transaction
-------------------------

Provide a class :class:`Transaction` gathering methods coming from
libmodsecurity.
"""
import sys
import weakref

from pymodsecurity._modsecurity import ffi as _ffi
from pymodsecurity._modsecurity import lib as _lib
from pymodsecurity.utils import as_bytes
from pymodsecurity.exceptions import (ProcessConnectionError,
                                      FeedingError,
                                      LoggingActionError)


_NULL = _ffi.NULL


class Transaction:
    """
    Wrapper for C functions built from **transaction.h** via CFFI.

    :param modsecurity: an instance of :class:`~modsecurity.ModSecurity`
    :param rules: an instance of :class:`~rules.Rules`
    """
    def __init__(self, modsecurity, rules, log_data=None):
        self._modsecurity = modsecurity
        self._rules = rules
        if log_data is None:
            log_data = _NULL
        else:
            log_data = _ffi.new_handle(log_data)
        self._log_callback_data = log_data

        self._status = 0
        self._pause = 0
        self._disruptive = 0
        self._url = _ffi.new("char *")
        self._log = _ffi.new("char *")
        self._intervention = _ffi.new("ModSecurityIntervention *",
                                      [self._status,
                                       self._pause,
                                       self._url,
                                       self._log,
                                       self._disruptive])

        self._transaction_struct = _lib.msc_new_transaction(
            self._modsecurity._modsecurity_struct,
            self._rules._rules_set,
            self._log_callback_data)
        assert self._transaction_struct != _NULL

    def __del__(self):
        _lib.msc_transaction_cleanup(self._transaction_struct)

    def process_connection(self,
                           client_ip, client_port,
                           server_ip, server_port):
        """
        Perform the analysis on the connection.

        This function should be called at very beginning of a request process,
        it is expected to be executed prior to the virtual host resolution,
        when the connection arrives on the server.

        :param client_ip: client's IP address as :class:`str`
        :param client_port: client's port as :class:`int`
        :param server_ip: server's IP address as :class:`str`
        :param server_port: server's port as :class:`int`

        .. note:: Remember to check for a possible intervention with
            :meth:`has_intervention()`.
        """
        retvalue = _lib.msc_process_connection(self._transaction_struct,
                                               as_bytes(client_ip),
                                               int(client_port),
                                               as_bytes(server_ip),
                                               int(server_port))
        if not retvalue:
            raise ProcessConnectionError.failed_at("connection")

    def process_uri(self, uri, method, http_version):
        """
        Perform the analysis on the URI and all the query string variables.

        This function should be called at very beginning of a request process,
        it is expected to be executed prior to the virtual host resolution,
        when the connection arrives on the server.

        :param uri: URI address
        :param method: an HTTP method
        :param http_version: a :class:`str` defining HTTP protocol version

        .. note::
            * Value consistency is not checked for ``method`` and
              ``http_version``.
            * Remember to check for a possible intervention
              with :meth:`has_intervention()`.
        """
        retvalue = _lib.msc_process_uri(self._transaction_struct,
                                        as_bytes(uri),
                                        as_bytes(method),
                                        as_bytes(http_version))
        if not retvalue:
            raise ProcessConnectionError.failed_at("uri")

    def process_request_headers(self):
        """
        Perform the analysis on the request headers.

        This function perform the analysis on the request headers, notice
        however that the headers should be added prior to the execution of
        this function or :exc:`~exceptions.ProcessConnectionError` will be
        raised.

        .. note:: Remember to check for a possible intervention
            with :meth:`has_intervention()`.
        """
        retvalue = _lib.msc_process_request_headers(self._transaction_struct)
        if not retvalue:
            raise ProcessConnectionError.failed_at("request headers")

    def add_request_header(self, key, value):
        """
        Add a request header to be inspected.

        With this function it is possible to feed ModSecurity with a request
        header.

        :param key: key of a request header
        :param value: value associated to ``key``
        """
        retvalue = _lib.msc_add_request_header(self._transaction_struct,
                                               as_bytes(key),
                                               as_bytes(value))
        if not retvalue:
            raise FeedingError.failed_at("request header")

    def append_request_body(self, body):
        """
        Add request body to be inspected.

        With this function it is possible to feed ModSecurity with data for
        inspection regarding the request body.
        There are two possibilities here:

            - Add the buffer in a row
            - Add it in chunks

        :param body: (chunk of the) body of a request
        """
        retvalue = _lib.msc_append_request_body(self._transaction_struct,
                                                as_bytes(body),
                                                len(body))
        if not retvalue:
            raise FeedingError.failed_at("request body")

    def get_request_body_from_file(self, filepath):
        """
        Add request body stored in a file to be inspected.

        :param filepath: path to a file
        """
        retvalue = _lib.msc_request_body_from_file(self._transaction_struct,
                                                   as_bytes(filepath))
        if not retvalue:
            raise FeedingError.failed_at("getting request body from file")

    def process_request_body(self):
        """
        Perform the analysis on the request body (if any).

        This function perform the analysis on the request body. It is optional
        to call that function. If this API consumer already know that there
        isn't a body for inspect it is recommended to skip this step.

        It is necessary to append the request body prior to the execution of
        this function or :exc:`~exceptions.ProcessConnectionError` will be
        raised.

        .. note:: Remember to check for a possible intervention
            with :meth:`has_intervention()`.
        """
        retvalue = _lib.msc_process_request_body(self._transaction_struct)
        if not retvalue:
            raise ProcessConnectionError.failed_at("request body")

    def process_response_headers(self, statuscode, protocol):
        """
        Perform the analysis on the response headers.

        This function perform the analysis on the response headers, notice
        however that the headers should be added prior to the execution of
        this function or :exc:`~exceptions.ProcessConnectionError` will be
        raised.

        :param statuscode: HTTP status code as :class:`int`
        :param protocol: protocol name with its version (e.g "HTTP 1.1")

        .. note:: Remember to check for a possible intervention
            with :meth:`has_intervention()`.
        """
        retvalue = _lib.msc_process_response_headers(self._transaction_struct,
                                                     int(statuscode),
                                                     as_bytes(protocol))
        if not retvalue:
            raise ProcessConnectionError.failed_at("response headers")

    def add_response_header(self, key, value):
        """
        Add a response header to be inspected.

        With this function it is possible to feed ModSecurity with a
        response header.

        :param key: key of an response header
        :param value: value associated to ``key``
        """
        retvalue = _lib.msc_add_response_header(self._transaction_struct,
                                                as_bytes(key),
                                                as_bytes(value))
        if not retvalue:
            raise FeedingError.failed_at("response header")

    def process_response_body(self):
        """
        Perform the analysis on the response body (if any).

        This function perform the analysis on the response body. It is optional
        to call that function. If this API consumer already know that there
        isn't a body for inspect it is recommended to skip this step.

        It is necessary to append the response body prior to the execution of
        this function or :exc:`~exceptions.ProcessConnectionError` will be
        raised.

        .. note:: Remember to check for a possible intervention
            with :meth:`has_intervention()`.
        """
        retvalue = _lib.msc_process_response_body(self._transaction_struct)
        if not retvalue:
            raise ProcessConnectionError.failed_at("response body")

    def append_response_body(self, body):
        """
        Add reponse body to be inspected.

        With this function it is possible to feed ModSecurity with data for
        inspection regarding the response body. ModSecurity can also update the
        contents of the response body, this is not quite ready yet on this
        version of libmodsecurity.

        If the content is updated, the client cannot receive the content length
        header filled, at least not with the old values. Otherwise unexpected
        behavior may happens.

        :param body: body of a response
        """
        retvalue = _lib.msc_append_response_body(self._transaction_struct,
                                                 as_bytes(body),
                                                 len(body))
        if not retvalue:
            raise FeedingError.failed_at("response body")

    def get_response_body(self):
        """
        Retrieve a buffer with the updated response body.

        This function is needed to be called whenever ModSecurity update the
        contents of the response body, otherwise there is no need to call this
        function.

        :return: buffer as :class:`str` containing the response body
        """
        returned_buffer = _lib.msc_get_response_body(self._transaction_struct)
        if returned_buffer == _NULL:
            return None

        return _ffi.string(returned_buffer)

    def get_response_body_length(self):
        """
        Retrieve the length of the updated response body.

        This function returns the size of the update response body buffer,
        notice however, that most likely there isn't an update.

        :return: length of the response body if there's an update
        """
        return _lib.msc_get_response_body_length(self._transaction_struct)

    def has_intervention(self):
        """
        Check if ModSecurity has anything to ask to the server.

        Intervention can generate a log event and/or perform a disruptive
        action depending on ``SecRuleEngine`` value in ModSecurity
        configuration file.
        This function only displays information about the current transaction
        so calling it has no side-effect.

        :return: ``True`` if a disrupive action has (to be) performed
        """
        return bool(_lib.msc_intervention(self._transaction_struct,
                                          self._intervention))

    def process_logging(self):
        """
        Log all information relative to this transaction into a log file where
        its path is defined by ``SecDebugLog`` value in ModSecurity
        configuration file.

        At this point there is not need to hold the connection, the response
        can be delivered prior to the execution of this function.
        """
        retvalue = _lib.msc_process_logging(self._transaction_struct)
        if not retvalue:
            raise LoggingActionError

    def get_matched_rules_info(self):
        """
        Retrieve the info associated to each matched rule. This include for
        each rule the the ID, the anomaly score, a message and the parameter
        which tiggered it.

        :return: :class:`list` of rule info contained in a :class:`tuple`
            formatted as ``(ID, score, message, parameter)``, ``None`` if no
            rules have been matched
        """
        value = _lib.msc_get_matched_rules_info(self._transaction_struct)

        result = []
        for i in range(value.size):
            result.append((value.rules_info[i].id,
                           value.rules_info[i].score,
                           _ffi.string(value.rules_info[i].message),
                           _ffi.string(value.rules_info[i].parameter)))
        return result
