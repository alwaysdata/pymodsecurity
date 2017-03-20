# -*- coding: utf-8 -*-

import cffi
import os


source_file = "modsecurity_transaction_rules_source.h"
cdef_file = "modsecurity_transaction_rules_cdef.h"
libraries = ["modsecurity"]

module_directory = os.path.abspath(os.path.dirname(__file__))
path_to_source = module_directory + "/build_src/" + source_file
path_to_cdef = module_directory + "/build_src/" + cdef_file

modsec_lib_name = "_modsecurity"

ffibuilder = cffi.FFI()

with open(path_to_source, 'r') as f:
    ffibuilder.set_source(modsec_lib_name, f.read(),
                          libraries=libraries,
                          library_dirs=[],
                          extra_link_args=[],)
with open(path_to_cdef, 'r') as f:
    ffibuilder.cdef(f.read())
