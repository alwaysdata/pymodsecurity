# coding: utf-8
"""
Test Rules methods.
"""

import contextlib
import os
import sys
import unittest
import unittest.mock

path = "../.."
if path not in sys.path:
    sys.path.insert(0, path)

from modsecurity import rules  # NOQA
from modsecurity._modsecurity import ffi  # NOQA
from modsecurity.exceptions import InternalError  # NOQA


class TestRules(unittest.TestCase):
    def setUp(self):
        self.rules_set = rules.Rules()

    @contextlib.contextmanager
    def assert_error_add_rules(self, msc_function):
        def _set_error_message(message):
            def side_effect(pointer, *pargs):
                charp = ffi.new("char []", message.encode())
                pointer = ffi.new("const char **", charp)
                self.rules_set._error_pointer = pointer
                return -1
            return side_effect

        with self.assertRaises(InternalError) as ctx:
            with unittest.mock.patch("modsecurity.rules._lib") as ffi_mock:
                # david : est-ce la bonne manière de faire pour mocker les 3
                # fonctions que je teste ? N'y a-t-il pas un moyen de récuprer
                # l'argument `msc_function` et faire quelque comme ffi_mock.msc_function.side_effect ?
                ffi_mock.msc_rules_add_remote.side_effect = _set_error_message("error message")
                ffi_mock.msc_rules_add_file.side_effect = _set_error_message("error message")
                ffi_mock.msc_rules_add.side_effect = _set_error_message("error message")
                yield
        self.assertEqual("error message", ctx.exception.args[0])

    def test__last_error_message(self):
        """
        Test private method :func:`_last_error_message` which is only used
        inside :func:`~modsecurity.rules.Rules.add_remote_rules`,
        :func:`~modsecurity.rules.Rules.add_rules_file`, and
        :func:`~modsecurity.rules.Rules.add_rules`.

        Since this function uses private attribute ``_error_pointer`` and
        perfom operations on it, it is necessary to expose and maniuplate here.
        """
        # david : On s'est qu'on virerait ce test mais j'ai toujours besoin de
        # tester si la valeur par défaut est bien retournée. Je garde le test donc ?
        default_error_message = "No information provided by libmodsecurity"
        self.assertEqual(self.rules_set._last_error_message(),
                         default_error_message)

        # After call test
        self.assertEqual(self.rules_set._error_pointer[0], ffi.NULL)

    #@unittest.skip("For DEBUG purpose")  # DEBUG
    def test_add_remote_rules(self):
        # Return nothing in case of success
        key = "test_key"
        uri = "https://www.modsecurity.org/modsecurity-regression-test-secremoterules.txt"
        self.rules_set.add_remote_rules(key, uri)

        # Empty key
        key = ""
        with self.assertRaises(InternalError):
            self.rules_set.add_remote_rules(key, uri)

        # Bad uri
        uri = "fake uri"
        with self.assertRaises(InternalError):
            self.rules_set.add_remote_rules(key, uri)

        with self.assert_error_add_rules("msc_rules_add_remote"):
            self.rules_set.add_remote_rules("test_of_assertion", "fake_uri")

    def test_add_rules_file(self):
        # Return nothing in case of success
        filename = "basic_rules.conf"
        filepath = os.path.abspath(os.path.dirname(__file__)) + "/" + filename
        self.rules_set.add_rules_file(filepath)

        # Fake file name
        filename = "fakefile"
        with self.assertRaises(InternalError):
            self.rules_set.add_rules_file(filename)

        with self.assert_error_add_rules("msc_rules_add_file"):
            self.rules_set.add_rules_file("test_of_assertion")

    def test_add_rules(self):
        # Return nothing in case of success
        plain_rule = ('SecRule REQUEST_HEADERS:Content-Type \"text/xml"' +
                      ' "id:\'200000\',phase:1,t:none,t:lowercase,pass,nolog,' +
                      'ctl:requestBodyProcessor=XML"')
        self.rules_set.add_rules(plain_rule)

        # Bad rule
        plain_rule = "spam eggs ham"
        with self.assertRaises(InternalError):
            self.rules_set.add_rules(plain_rule)

        with self.assert_error_add_rules("msc_rules_add"):
            self.rules_set.add_rules("test_of_assertion")

    def test_merge_rules(self):
        self.rules_set1 = rules.Rules()
        self.rules_set2 = rules.Rules()

        rule_1 = ('SecRule REQUEST_HEADERS:Content-Type \"text/xml"' +
                  ' "id:\'200000\',phase:1,t:none,t:lowercase,pass,nolog,' +
                  'ctl:requestBodyProcessor=XML"')
        rule_2 = ('SecRule REQUEST_HEADERS:Content-Type \"application/json"' +
                  ' "id:\'200001\',phase:1,t:none,t:lowercase,pass,nolog,' +
                  'ctl:requestBodyProcessor=JSON"')
        self.rules_set1.add_rules(rule_1)
        self.rules_set2.add_rules(rule_2)
        self.assertEqual(self.rules_set1.merge_rules(self.rules_set2), 1)

        # Rules() instance without any rules
        self.rules_set3 = rules.Rules()
        self.assertEqual(self.rules_set1.merge_rules(self.rules_set3), 0)
