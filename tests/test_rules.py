# coding: utf-8
"""
Test Rules methods.
"""

import contextlib
import os
import unittest
import unittest.mock

from pymodsecurity import rules
from pymodsecurity._modsecurity import ffi
from pymodsecurity.exceptions import InternalError


class TestRules(unittest.TestCase):
    def setUp(self):
        self.rules_set = rules.Rules()

    @contextlib.contextmanager
    def assert_add_rules_error_message_raised(self, msc_function):
        message = "error message"

        def _side_effect(*pargs):
            charp = ffi.new("char []", message.encode())
            pointer = ffi.new("const char **", charp)
            self.rules_set._error_pointer = pointer
            return -1

        with self.assertRaises(InternalError) as ctx:
            with unittest.mock.patch("pymodsecurity.rules._lib") as ffi_mock:
                getattr(ffi_mock, msc_function).side_effect = _side_effect
                yield
        self.assertEqual("error message", ctx.exception.args[0])

    def test__last_error_message(self):
        """
        Test private method :func:`_last_error_message` which is only used
        inside :func:`~pymodsecurity.rules.Rules.add_rules_remote`,
        :func:`~pymodsecurity.rules.Rules.add_rules_file`, and
        :func:`~pymodsecurity.rules.Rules.add_rules`.

        Since this function uses private attribute ``_error_pointer`` and
        perfom operations on it, it is necessary to expose and maniuplate here.
        """
        default_error_message = "No information provided by libmodsecurity"
        self.assertEqual(self.rules_set._last_error_message(),
                         default_error_message)

        # After call test
        self.assertEqual(self.rules_set._error_pointer[0], ffi.NULL)

    def test_add_rules_remote(self):
        # Good use
        key = "test_key"
        uri = "https://www.modsecurity.org/modsecurity-regression-test-secremoterules.txt"
        retvalue = self.rules_set.add_rules_remote(key, uri)
        self.assertEqual(retvalue, 1)

        # Empty key
        with self.assertRaises(InternalError):
            self.rules_set.add_rules_remote("", uri)

        # Bad uri
        with self.assertRaises(InternalError):
            self.rules_set.add_rules_remote(key, "fake_uri")

        with self.assert_add_rules_error_message_raised("msc_rules_add_remote"):
            self.rules_set.add_rules_remote("test_of_assertion", "fake_uri")

    def test_add_rules_file(self):
        # Good use
        filename = "basic_rules.conf"
        filepath = os.path.abspath(os.path.dirname(__file__)) + "/" + filename
        retvalue = self.rules_set.add_rules_file(filepath)
        self.assertEqual(retvalue, 7)

        # Fake file name
        with self.assertRaises(InternalError):
            self.rules_set.add_rules_file("fakefile")

        with self.assert_add_rules_error_message_raised("msc_rules_add_file"):
            self.rules_set.add_rules_file("test_of_assertion")

    def test_add_rules(self):
        # Good use
        plain_rule = ('SecRule REQUEST_HEADERS:Content-Type "text/xml"' +
                      ' "id:\'200000\',phase:1,t:none,t:lowercase,pass,nolog,' +
                      'ctl:requestBodyProcessor=XML"')
        retvalue = self.rules_set.add_rules(plain_rule)
        self.assertEqual(retvalue, 1)

        # Bad rule
        with self.assertRaises(InternalError):
            self.rules_set.add_rules("spam eggs ham")

        with self.assert_add_rules_error_message_raised("msc_rules_add"):
            self.rules_set.add_rules("test_of_assertion")

    def test_merge_rules(self):
        self.rules_set1 = rules.Rules()
        self.rules_set2 = rules.Rules()

        rule_1 = ('SecRule REQUEST_HEADERS:Content-Type "text/xml"' +
                  ' "id:\'200000\',phase:1,t:none,t:lowercase,pass,nolog,' +
                  'ctl:requestBodyProcessor=XML"')
        rule_2 = ('SecRule REQUEST_HEADERS:Content-Type "application/json"' +
                  ' "id:\'200001\',phase:1,t:none,t:lowercase,pass,nolog,' +
                  'ctl:requestBodyProcessor=JSON"')
        self.rules_set1.add_rules(rule_1)
        self.rules_set2.add_rules(rule_2)
        self.assertEqual(self.rules_set1.merge_rules(self.rules_set2), 1)

        # Rules() instance without any rules
        self.rules_set3 = rules.Rules()
        self.assertEqual(self.rules_set1.merge_rules(self.rules_set3), 0)
