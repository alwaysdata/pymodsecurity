#! python3
# coding: utf-8

from _modsecurity import ffi as _ffi
from _modsecurity import lib as _lib
from modsecurity.exceptions import InputError
from modsecurity.exceptions import FileOpeningError
from modsecurity.exceptions import FetchRemoteFileError
from modsecurity.exceptions import RuleWrittingError


class Rules:
    """
    Wrapper for C function built from rules.h via CFFI.
    """
    def __init__(self,):
        _rules_set = self.create_rule_set()
        assert(_rules_set != _ffi.NULL)
        _rules_set = _ffi.gc(_rules_set, _lib.msc_rules_cleanup)

        self._rules_set = _rules_set
        self._error = _ffi.new('char [256]')
        self._error_pointer = _ffi.new('const char **', self._error)

    def create_rule_set(self):
        return _lib.msc_create_rules_set()

    def dump_rules(self):
        return _lib.msc_rules_dump(self._rules_set)

    def merge_rules(self, OtherRules):
        return _lib.msc_rules_merge(self._rules_set,
                                    OtherRules._rules_set)

    def add_remote_rules(self, key, uri):
        try:
            key = bytes(key.encode())
            uri = bytes(uri.encode())
        except:
            raise InputError
            return

        value = _lib.msc_rules_add_remote(self._rules_set,
                                          key,
                                          uri,
                                          self._error_pointer)
        if value == -1:
            raise FetchRemoteFileError

    def add_rules_file(self, filename):
        filename = bytes(filename.encode())
        value = _lib.msc_rules_add_file(self._rules_set,
                                        filename,
                                        self._error_pointer)
        if value == -1:
            raise FileOpeningError

    def add_rules(self, plain_rules):
        plain_rules = bytes(plain_rules.encode())
        value = _lib.msc_rules_add(self._rules_set,
                                   plain_rules,
                                   _ffi._error)
        if value == -1:
            raise RuleWrittingError


if __name__ == '__main__':
    # Self-testing section
    filename = '/home/soonum/Code/alwaysdata/ModSecurity/examples/simple_example_using_c/basic_rules.conf'  # DEBUG
    key = 'test'
    uri = 'https://www.modsecurity.org/modsecurity-regression-test-secremoterules.txt'  # DEBUG

    x = Rules()
    y = Rules()

    print('Adding rules file...', flush=True)
    x.add_rules_file(filename)
    print('Adding remote rules file...', flush=True)
    y.add_remote_rules(key, uri)
    print('Merging rules...', flush=True)
    x.merge_rules(y)
    print('Dumping rules...', flush=True)
    x.dump_rules()
    print('Cleaning rules...', flush=True)
    x.cleanup_rules()
    print('\nTrying to dump rules again # 1...', flush=True)
    x.dump_rules()
    print('\nAdding rules file with bad path...', flush=True)
    x.add_rules_file('nofile')
