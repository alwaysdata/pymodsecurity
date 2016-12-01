# coding: utf-8
"""
Test Transaction methods.
"""

import contextlib
import os
import unittest
import unittest.mock

from pymodsecurity import transaction
from pymodsecurity.modsecurity import ModSecurity
from pymodsecurity.rules import Rules
from pymodsecurity.exceptions import (ProcessConnectionError,
                                      FeedingError,
                                      LoggingActionError)


class TestTransaction(unittest.TestCase):
    """
    All methods except :meth:`~TestTransaction.get_response_body_length`
    and :meth:`~TestTransaction.has_intervention` return nothing in case of
    success.
    """
    def setUp(self):
        self.transactions = transaction.Transaction(ModSecurity(), Rules())
        self.body = "This is a body"

    @contextlib.contextmanager
    def assert_error_message_raised(self, msc_function, expected_exception,
                                    return_value=0):

        def _create_mock(*pargs):
            mock = unittest.mock.Mock(return_value=return_value)
            return mock()

        with self.assertRaises(expected_exception):
            with unittest.mock.patch("pymodsecurity.transaction._lib") as ffi_mock:
                getattr(ffi_mock, msc_function).side_effect = _create_mock
                yield

    def test_process_connection(self):
        client_ip = "127.0.0.1"
        client_port = 12345
        server_ip = "127.0.0.1"
        server_port = 80
        self.transactions.process_connection(client_ip,
                                             client_port,
                                             server_ip,
                                             server_port)

        with self.assert_error_message_raised("msc_process_connection",
                                              ProcessConnectionError):
            self.transactions.process_connection(client_ip,
                                                 client_port,
                                                 server_ip,
                                                 server_port)

    def test_process_uri(self):
        uri = "http://www.modsecurity.org/test?key1=value1&key2=value2&key3=value3"
        method = "GET"
        http_version = "1.1"
        self.transactions.process_uri(uri, method, http_version)

        # Lower case method:
        self.transactions.process_uri(uri, "get", http_version)

        with self.assert_error_message_raised("msc_process_uri",
                                              ProcessConnectionError):
            self.transactions.process_uri(uri, method, http_version)

    def test_add_request_header(self):
        key = "Expect"
        value = "100-continue"
        self.transactions.add_request_header(key, value)

        with self.assert_error_message_raised("msc_add_request_header",
                                              FeedingError):
            self.transactions.add_request_header(key, value)

    def test_append_request_body(self):
        self.transactions.append_request_body(self.body)

        with self.assert_error_message_raised("msc_append_request_body",
                                              FeedingError):
            self.transactions.append_request_body(self.body)

    def test_get_request_body_from_file(self):
        filename = "http_body_testfile"
        filepath = os.path.abspath(os.path.dirname(__file__)) + "/" + filename

        if not os.path.isfile(filepath):
            with open(filepath, 'w') as f:
                f.write("This is a body in a file\n")

        self.transactions.get_request_body_from_file(filepath)

        with self.assert_error_message_raised("msc_request_body_from_file",
                                              ProcessConnectionError):
            self.transactions.get_request_body_from_file(filepath)

    def test_process_request_headers(self):
        self.transactions.add_request_header("Expect", "100-continue")
        self.transactions.process_request_headers()

        with self.assert_error_message_raised("msc_process_request_headers",
                                              ProcessConnectionError):
            self.transactions.process_request_headers()

    def test_process_request_body(self):
        self.transactions.append_request_body(self.body)
        self.transactions.process_request_body()

        with self.assert_error_message_raised("msc_process_request_body",
                                              ProcessConnectionError):
            self.transactions.process_request_body()

    def test_add_response_header(self):
        key = "Accept-Ranges"
        value = "bytes"
        self.transactions.add_response_header(key, value)

        with self.assert_error_message_raised("msc_add_response_header",
                                              FeedingError):
            self.transactions.add_response_header(key, value)

    def test_append_response_body(self):
        self.transactions.append_response_body(self.body)

        with self.assert_error_message_raised("msc_append_response_body",
                                              FeedingError):
            self.transactions.append_response_body(self.body)

    def test_get_response_body(self):
        # Regular use of get_response_body_length() cannot be tested in unit
        # test since libmodsecurity has to update the body to return its length.

        # Body not updated
        self.assertEqual(self.transactions.get_response_body(), b"")

    def test_get_response_body_length(self):
        # Regular use of get_response_body_length() cannot be tested in unit
        # test since libmodsecurity has to update the body to return its length.

        # Body not updated
        self.assertEqual(self.transactions.get_response_body_length(), 0)

    def test_process_response_headers(self):
        self.transactions.add_response_header("Accept-Ranges", "bytes")
        self.transactions.process_response_headers(200, "HTTP 1.1")

        with self.assert_error_message_raised("msc_process_response_headers",
                                              ProcessConnectionError):
            self.transactions.process_response_headers(200, "HTTP 1.1")

    def test_process_response_body(self):
        self.transactions.append_response_body(self.body)
        self.transactions.process_response_body()

        with self.assert_error_message_raised("msc_process_response_body",
                                              ProcessConnectionError):
            self.transactions.process_response_body()

    def test_has_intervention(self):
        self.assertFalse(self.transactions.has_intervention())

    def test_process_logging(self):
        self.transactions.process_logging()

        with self.assert_error_message_raised("msc_process_logging",
                                              LoggingActionError):
            self.transactions.process_logging()
