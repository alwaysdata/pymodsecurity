#! python3
# coding: utf-8

from modsecurity import utils
from modsecurity._modsecurity import ffi as _ffi
from modsecurity._modsecurity import lib as _lib
from modsecurity.exceptions import InternalError


_NULL = _ffi.NULL


class Rules:
    """
    Wrapper for C function built from rules.h via CFFI.
    """
    def __init__(self,):
        _rules_set = _lib.msc_create_rules_set()
        assert _rules_set != _NULL
        _rules_set = _ffi.gc(_rules_set, _lib.msc_rules_cleanup)

        self._rules_set = _rules_set
        self._error_pointer = _ffi.new('const char **', _NULL)

    def get_error_message(self, error_pointer):
        """
        Retrieve error string pointed by error_pointer.
        This string is issued by libmodsecurity.
        """
        error_message = utils.text(error_pointer[0])
        if not error_message:
            error_message = "No information provided by libmodsecurity"

        error_pointer[0] = _NULL
        return error_message

    def dump_rules(self):
        _lib.msc_rules_dump(self._rules_set)

    def merge_rules(self, other_rules):
        """
        Merging a rules set into another one.

        Return the number of rules merged.
        """
        return _lib.msc_rules_merge(self._rules_set,
                                    other_rules._rules_set)

    def add_remote_rules(self, key, uri):
        """
        Fetch rules over a network and merge it
        with the current rules set.
        """
        key = utils.encode_string(key)
        uri = utils.encode_string(uri)
        retvalue = _lib.msc_rules_add_remote(self._rules_set,
                                             key,
                                             uri,
                                             self._error_pointer)
        if retvalue == -1:
            message = self.get_error_message(self._error_pointer)
            raise InternalError(message)

    def add_rules_file(self, filename):
        filename = utils.encode_string(filename)
        retvalue = _lib.msc_rules_add_file(self._rules_set,
                                           filename,
                                           self._error_pointer)
        if retvalue == -1:
            message = self.get_error_message(self._error_pointer)
            raise InternalError(message)

    def add_rules(self, plain_rules):
        """
        Add custom rule defined by `plain rules` and merge
        it with the current rules set.
        """
        plain_rules = utils.encode_string(plain_rules)
        retvalue = _lib.msc_rules_add(self._rules_set,
                                      plain_rules,
                                      self._error_pointer)
        if retvalue == -1:
            message = self.get_error_message(self._error_pointer)
            raise InternalError(message)


if __name__ == '__main__':
    # Self-testing section
    # Have to turn it into a unit test
    filename = '/home/soonum/Code/alwaysdata/ModSecurity/examples/simple_example_using_c/basic_rules.conf'  # DEBUG
    key = 'test'
    uri = 'https://www.modsecurity.org/modsecurity-regression-test-secremoterules.txt'  # DEBUG

    x = Rules()
    y = Rules()

    print('Adding rules file...', flush=True)
    x.add_rules_file(filename)
    print('Adding remote rules file...', flush=True)
    y.add_remote_rules(key, uri)
    print('Dumping rules...', flush=True)
    x.dump_rules()
    print('\nTrying to dump rules again # 1...', flush=True)
    x.dump_rules()
    print('\nAdding rules file with bad path...', flush=True)
    x.add_rules_file('nofile')
