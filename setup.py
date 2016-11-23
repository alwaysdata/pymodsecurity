#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Installation script for the pymodsecurity package.
"""
import codecs
import os
import re

from setuptools import setup, find_packages

from pymodsecurity import build_pymodsecurity

possible_modsecurity_dirs = [
    "/usr/local/modsecurity/",
    "/usr/",
    "/usr/local/",
    "./pymodsecurity/",
    ]
libraries_dir = [
    "lib/",
    "lib64/"
    ]
HERE = os.path.abspath(os.path.dirname(__file__))
META_PATH = os.path.join("pymodsecurity", "version.py")


def read_file(*parts):
    """
    Build an absolute path from ``parts`` and and return the contents of the
    resulting file. Assume UTF-8 encoding.
    """
    with codecs.open(os.path.join(HERE, *parts), "rb", "ascii") as f:
        return f.read()


META_FILE = read_file(META_PATH)


def find_meta(meta):
    """
    Extract __*meta*__ from META_FILE.
    """
    meta_match = re.search(
        r"^__{meta}__ = ['\"]([^'\"]*)['\"]".format(meta=meta),
        META_FILE, re.M
    )
    if meta_match:
        return meta_match.group(1)
    raise RuntimeError("Unable to find __{meta}__ string.".format(meta=meta))


def find_libmodsecurity():
    """
    Try to find ``libmodsecurity.so`` by looking into ``possible_modsecurity_dirs``
    and ``libraries_dir``.

    :return: path to directory containing ``libmodsecurity.so``
    """
    for i in possible_modsecurity_dirs:
        lib_directory = None

        for j in libraries_dir:
            filepath = os.path.join(i, j, "libmodsecurity.so")
            if os.path.nisfile(filepath) or os.path.islink(filepath):
                lib_directory = os.path.join(i, j)
                return lib_directory
    else:
        raise FileNotFoundError


def set_setup_parameters():
    setup_parameters = dict(
        name=find_meta("title"),
        version=find_meta("version"),
        description=find_meta("summary"),
        author=find_meta("author"),
        author_email=find_meta("email"),
        url=find_meta("uri"),
        license=find_meta("license"),
        classifiers=[
            "Development Status :: 4 - Beta",
            "Intended Audience :: Developers",
            "License :: OSI Approved :: Apache Software License",
            "Operating System :: GNU/Linux",

            "Programming Language :: Python :: 3.3",
            "Programming Language :: Python :: 3.4",
            "Programming Language :: Python :: 3.5",

            "Programming Language :: Python :: Implementation :: CPython",

            "Topic :: Security",
            "Topic :: Internet :: WWW/HTTP"
        ],
        packages=find_packages(where="pymodsecurity",
                               exclude=["build_pymodsecurity",
                                        "build_src",
                                        "tests"]),
    )

    return setup_parameters


if __name__ == "__main__":
    lib_directory = find_libmodsecurity()
    build_pymodsecurity.build_library(lib_directory)
    parameters = set_setup_parameters()
    setup(**parameters)
