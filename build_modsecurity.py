#! python3
# coding: utf-8

import cffi
import os


source_file = "modsecurity_transaction_rules_source.h"
cdef_file = "modsecurity_transaction_rules_cdef.h"
libraries = ["modsecurity"]
working_directory = os.path.abspath(os.path.dirname(__file__))

path_to_libraries = working_directory + "/lib/"
if not os.path.isdir(path_to_libraries):
    message = path_to_libraries + " doesn't exist"
    raise FileNotFoundError(message)

path_to_source = working_directory + "/build_src/" + source_file
path_to_cdef = working_directory + "/build_src/" + cdef_file
if not os.path.isfile(path_to_source) or not os.path.isfile(path_to_cdef):
    message = source_file + " or " + cdef_file + " don't exist"
    raise FileNotFoundError(message)


ffibuilder = cffi.FFI()

with open(path_to_source, 'r') as f:
    ffibuilder.set_source("_modsecurity",
                          f.read(),
                          library_dirs=[path_to_libraries],
                          libraries=libraries)

with open(path_to_cdef, 'r') as f:
    ffibuilder.cdef(f.read())

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
