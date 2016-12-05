Instructions
============

Installation
------------

pymodsecurity requires Python 3.3 or greater and the following packages:

  - cffi
  - setuptools
  - libmodsecurity

Note :
  - make sure that libmodsecurity version is 3.0.0 or greater.
  - all libmodsecurity.so files must be visible in standard library path,
    it can be done by using symlinks like so:

.. code-block:: bash

       $ sudo ln -s /current/path/to/libmodsecurity.so /standard/path/to/lib/libmodsecurity.so

pymodsecurity uses setuptools, so you can install it using :

.. code-block:: bash

        $ python3 setup.py build
	$ sudo python3 setup.py install

Documentation
-------------

If sphinx is installed, build the documentation :

.. code-block:: bash

    $ cd ./doc
    $ make html

Browse it from http://localhost:8000/ with :

.. code-block:: bash

    $ cd doc/_build/html && python -m http.server

Tests
-----

You can run unit tests by doing :

.. code-block:: bash

    $ cd ./tests
    $ python3 -m unittest -v

It will look for ``tests`` name based directories and perform all tests in them.
