Instructions
============

Installation
------------

pymodsecurity requires Python 3.3 or greater and the following packages:

  - cffi
  - setuptools
  - libmodsecurity (C library)

And optionally for the documentation:

  - sphinx
  - sphinx_rtd_theme

Note:

  - make sure that ``libmodsecurity`` version is 3.0.0 or greater.
  - all ``libmodsecurity.so`` files must be visible in standard library path,
    it can be done by using symlinks like so:

.. code-block:: bash

       $ ln -s /current/path/to/libmodsecurity.so /standard/path/to/lib/libmodsecurity.so

pymodsecurity uses setuptools, so you can install it using:

.. code-block:: bash

        $ python3 setup.py build
	$ python3 setup.py install

``libmodsecurity`` is not yet stable, and you may want to install it locally
rather than on the system. Once ``libmodsecurity`` is installed (for instance
in ``/opt/libmodsecurity``), you can use it by doing:

.. code-block:: bash

        $ OPT=/opt/libmodsecurity
        $ LIBRARY_PATH=$OPT/lib LD_LIBRARY_PATH=$OPT/lib C_INCLUDE_PATH=$OPT/include python setup.py install

and later, invoke your python script using ``libmodsecurity`` with:

.. code-block:: bash

        $ LD_LIBRARY_PATH=$OPT/lib python my_program.py


Documentation
-------------

If sphinx is installed, build the documentation:

.. code-block:: bash

    $ cd ./doc
    $ make html

Browse it from http://localhost:8000/ with:

.. code-block:: bash

    $ cd doc/_build/html && python -m http.server

Tests
-----

You can run unit tests by doing:

.. code-block:: bash

    $ python3 setup.py test

It will look for ``tests`` name based directories and perform all tests in them.
