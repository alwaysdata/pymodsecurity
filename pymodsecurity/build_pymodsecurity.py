# -*- coding: utf-8 -*-

import cffi
import os


source_file = "modsecurity_transaction_rules_source.h"
cdef_file = "modsecurity_transaction_rules_cdef.h"
libraries = ["modsecurity"]

working_directory = os.path.abspath(os.path.dirname(__file__))
path_to_source = working_directory + "/build_src/" + source_file
path_to_cdef = working_directory + "/build_src/" + cdef_file

modsec_lib_name = "_modsecurity"

ffibuilder = cffi.FFI()

try:
    with open(path_to_source, 'r') as f:
        ffibuilder.set_source(modsec_lib_name,
                              f.read(),
                              libraries=libraries,)
except FileNotFoundError:
    raise

try:
    with open(path_to_cdef, 'r') as f:
        ffibuilder.cdef(f.read())
except FileNotFoundError:
    raise
