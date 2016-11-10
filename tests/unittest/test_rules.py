# coding: utf-8
"""
Test Rules methods.
"""

import unittest
import os
import sys

path = "../../.."
if path not in sys.path:
    sys.path.insert(0, path)

from modsecurity import rules  # NOQA
from modsecurity._modsecurity import ffi  # NOQA
from modsecurity.exceptions import InternalError  # NOQA 


class TestRules(unittest.TestCase):
    def test_get_error_message(self):
        rules_set = rules.Rules()

        # Pointer init test
        self.assertEqual(rules_set._error_pointer[0], rules._NULL)

        default_error_message = "No information provided by libmodsecurity"
        self.assertEqual(rules_set.get_error_message(rules_set._error_pointer), default_error_message)

        charp = ffi.new("char []", b"error message")
        rules_set._error_pointer = ffi.new("const char **", charp)
        self.assertEqual(rules_set.get_error_message(rules_set._error_pointer), "error message")

        # After call test:
        self.assertEqual(rules_set._error_pointer[0], rules._NULL)

    #@unittest.skip("For DEBUG purpose")  # DEBUG
    def test_add_remote_rules(self):
        rules_set = rules.Rules()

        # Return nothing in case of success
        key = "test_key"
        uri = "https://www.modsecurity.org/modsecurity-regression-test-secremoterules.txt"  # Utilisation du réseau, pas très recommandé dans un unit test non ? Mais comment faire autrement sinon ? (l'exécution de cette fonction est lente en plus de ça)
        rules_set.add_remote_rules(key, uri)

        # Empty key
        key = ""
        with self.assertRaises(InternalError):
            rules_set.add_remote_rules(key, uri)

        # Bad uri
        uri = "fake uri"
        with self.assertRaises(InternalError):
            rules_set.add_remote_rules(key, uri)

    def test_add_rules_file(self):
        rules_set = rules.Rules()

        # Return nothing in case of success
        filename = "basic_rules.conf"  # Appel I/O, pas très recommandé dans un unit test non ?
        filepath = os.path.abspath(os.path.dirname(__file__)) + "/" + filename
        rules_set.add_rules_file(filepath)

        # Fake file name
        filename = "fakefile"
        with self.assertRaises(InternalError):
            rules_set.add_rules_file(filename)

    def test_add_rules(self):
        rules_set = rules.Rules()

        # Return nothing in case of success
        plain_rule = ("SecRule REQUEST_HEADERS:Content-Type \"text/xml\"" +
                      " \"id:'200000',phase:1,t:none,t:lowercase,pass,nolog," +
                      "ctl:requestBodyProcessor=XML\"")
        rules_set.add_rules(plain_rule)

        # Bad rule
        plain_rule = "spam eggs ham"
        with self.assertRaises(InternalError):
            rules_set.add_rules(plain_rule)

    def test_merge_rules(self):
        rules_set1 = rules.Rules()
        rules_set2 = rules.Rules()

        rule_1 = ("SecRule REQUEST_HEADERS:Content-Type \"text/xml\"" +
                  " \"id:'200000',phase:1,t:none,t:lowercase,pass,nolog," +
                  "ctl:requestBodyProcessor=XML\"")
        rule_2 = ("SecRule REQUEST_HEADERS:Content-Type \"application/json\"" +
                  " \"id:'200001',phase:1,t:none,t:lowercase,pass,nolog," +
                  "ctl:requestBodyProcessor=JSON\"")
        rules_set1.add_rules(rule_1)
        rules_set2.add_rules(rule_2)
        #self.assertEqual(rules_set1.merge_rules(rules_set2), 1)  # Uncomment this test after recompiling libmodsecurity with the patch i've made (waiting for pull request)
        self.assertEqual(rules_set1.merge_rules(rules_set2), 0)  # Delete this line after recompiling

        # Rules() instance without any rules
        rules_set3 = rules.Rules()
        self.assertEqual(rules_set1.merge_rules(rules_set3), 0)

    def test_dump_rules(self):
        pass
