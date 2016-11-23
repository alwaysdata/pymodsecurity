# -*- coding: utf-8 -*-

import cffi
import os


source_file = "modsecurity_transaction_rules_source.h"
cdef_file = "modsecurity_transaction_rules_cdef.h"
libraries = ["modsecurity"]
working_directory = os.path.abspath(os.path.dirname(__file__))

# If libmodsecurity is used locally, *.so files MUST be located modsecurity/lib
path_to_libraries = working_directory + "/lib/"
if not os.path.isdir(path_to_libraries):
    message = path_to_libraries + " doesn't exist"
    raise FileNotFoundError(message)

path_to_source = working_directory + "/build_src/" + source_file
path_to_cdef = working_directory + "/build_src/" + cdef_file
if not os.path.isfile(path_to_source) or not os.path.isfile(path_to_cdef):
    message = source_file + " or " + cdef_file + " doesn't exist"
    raise FileNotFoundError(message)


def build_library(libpath=None):
    """
    Build _modsecurity-cpython-<version>.so CFFI library.

    :param libpath: path to ``libmodsecurity.so``
    """
    if not libpath:
        # Local library
        libpath = path_to_libraries

    modsec_lib_name = "_modsecurity"
    ffibuilder = cffi.FFI()

    with open(path_to_source, 'r') as f:
        ffibuilder.set_source(modsec_lib_name,
                              f.read(),
                              library_dirs=[libpath],
                              libraries=libraries,
                              runtime_library_dirs=[libpath])

    with open(path_to_cdef, 'r') as f:
        ffibuilder.cdef(f.read())

    ffibuilder.compile(verbose=True)

    # Clean compilation related files
    os.remove("_modsecurity.c")
    os.remove("_modsecurity.o")

    # Move _modsecurity shared object to modsecurity package
    dir_content = os.listdir()
    for item in dir_content:
        if modsec_lib_name + ".cpython" in item and ".so" in item:
            modsecurity_lib = item
            break
    else:
        return
    new_path = working_directory + "/" + modsecurity_lib
    os.rename(modsecurity_lib, new_path)
