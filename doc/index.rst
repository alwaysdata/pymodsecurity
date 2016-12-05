.. pymodsecurity documentation master file, created by
   sphinx-quickstart on Wed Nov 30 11:21:41 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

pymodsecurity
=============

pymodsecurity is a package providing Python bindings for libmodsecurity which is a
part of `ModSecurity <https://www.modsecurity.org/>`_ project.
pymodsecurity uses the C interface exposed in libmodsecurity (v3.0.0) sources.

This API is built using `CFFI <https://cffi.readthedocs.io/en/latest/index.html>`_.

Content
-------

.. toctree::
   :maxdepth: 2
   :caption: Installation

   README

.. toctree::
   :maxdepth: 2
   :caption: Modules
	      
   modsecurity
   rules
   transaction
   exceptions

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

