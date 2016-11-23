# -*- coding: utf-8 -*-
"""
Test Transaction methods.
"""

import sys
import unittest

path = "../.."  # NOQA
if path not in sys.path:  # NOQA
    sys.path.insert(0, path)  # NOQA

from pymodsecurity import modsecurity


class TestModsecurity(unittest.TestCase):
    def setUp(self):
        self.modsec = modsecurity.ModSecurity()

    def test_set_connector_info(self):
        connector = "Connector vX.Y.Z-tag"
        # Return nothing in case of success
        self.modsec.set_connector_info(connector)

    def test_set_log_callback(self):
        # FIXME : has to be implemented
        pass

    def test_who_am_i(self):
        version = "v3.0.0"
        connector = "ModSecurity " + version
        retvalue = self.modsec.who_am_i()
        self.assertIn(connector, retvalue)
