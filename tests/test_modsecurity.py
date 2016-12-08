# -*- coding: utf-8 -*-
"""
Test Modsecurity methods.
"""

import os
import unittest

from pymodsecurity import modsecurity
from pymodsecurity import transaction
from pymodsecurity import rules


class TestModsecurity(unittest.TestCase):
    def setUp(self):
        self.modsec = modsecurity.ModSecurity()

    def test_set_connector_info(self):
        connector = "Connector vX.Y.Z-tag"
        # Return nothing in case of success
        self.modsec.set_connector_info(connector)

    def test_set_log_callback(self):

        def dummy_callback(data, message):
            nonlocal callback_called
            nonlocal data_object_returned
            callback_called = True
            data_object_returned = data

        def dummy_data_oject():
            data1 = "data"
            data2 = "object"
            return (data1, data2)

        callback_called = False
        data_object_returned = None

        self.modsec.set_log_callback(dummy_callback)
        data_object = dummy_data_oject()

        # Setting up a context to trigger a log event.
        filename = "basic_rules.conf"
        filepath = os.path.abspath(os.path.dirname(__file__)) + "/" + filename

        rule = rules.Rules()
        rule.add_rules_file(filepath)
        transac = transaction.Transaction(self.modsec, rule, data_object)
        transac.process_connection("127.0.0.1", 12345,
                                   "127.0.0.1", 80)
        transac.process_uri("http://www.modsecurity.org/",
                            "GET",
                            "1.1")
        transac.add_request_header("SPAM\n", "test")
        transac.process_request_headers()

        self.assertTrue(callback_called)
        self.assertEqual(data_object_returned, ("data", "object"))

    def test_who_am_i(self):
        version = "v3.0.0"
        connector = "ModSecurity " + version
        retvalue = self.modsec.who_am_i()
        self.assertIn(connector, retvalue)
