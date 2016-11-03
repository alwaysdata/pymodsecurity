#! python3
# coding: utf-8

import cffi

# Static path to the libraries.
# Has to be changed to be user independant.
path_to_libraries = ["/home/soonum/Code/alwaysdata/ModSecurity/examples/cffi_tests/modsecurity/lib/"]
libraries = ["modsecurity"]
path = "/home/soonum/Code/alwaysdata/ModSecurity/examples/cffi_tests/modsecurity_includes_clean/"
path_to_headers = path + "modsecurity_transaction_rules_headers.h"
path_to_source = path + "modsecurity_transaction_rules_cleaned.h"

ffibuilder = cffi.FFI()

with open(path_to_headers, 'r') as f:
    ffibuilder.set_source("_modsecurity",
                          f.read(),
                          library_dirs=path_to_libraries,
                          libraries=libraries)

with open(path_to_source, 'r') as f:
    ffibuilder.cdef(f.read())

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
