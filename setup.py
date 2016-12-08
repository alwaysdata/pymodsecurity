#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Installation script for the pymodsecurity package.
"""
from setuptools import setup

from pymodsecurity import version


setup_parameters = dict(
    name=version.__title__,
    version=version.__version__,
    description=version.__summary__,
    author=version.__author__,
    author_email=version.__email__,
    url=version.__uri__,
    license=version.__license__,
    classifiers=[
        "Development Status :: 2 - Dev",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",

        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: Implementation :: CPython",

        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP"
    ],
    packages=["pymodsecurity"],

    setup_requires=["cffi>=1.8.0"],
    install_requires=["cffi>=1.8.0",
                      "sphinx_rtd_theme"],
    cffi_modules=["pymodsecurity/build_pymodsecurity.py:ffibuilder"],
    ext_package="pymodsecurity",

    test_suite="tests",
)


if __name__ == "__main__":
    setup(**setup_parameters)
