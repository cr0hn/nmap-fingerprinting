nmap-fingerprinting
===================

**Nmap-fingerprinting: Use Nmap fingerprinting rules, from Python and without call Nmap**


Usage
=====

Installing from Pypi
--------------------

.. code-block:: bash

    > python3.6 -m pip install nmap-fingerprinting

From source
-----------

.. code-block:: bash

    > git clone https://github.com/cr0hn/nmap-fingerprinting.git
    > cd nmap-fingerprinting/
    > python3.6
    Python 3.6.4 (default, Jan  6 2018, 11:51:59)
    [GCC 4.2.1 Compatible Apple LLVM 9.0.0 (clang-900.0.39.2)] on darwin
    Type "help", "copyright", "credits" or "license" for more information.
    >>> import nmap_fingerprinting
    >>> res = NmapServiceProbes()
    >>> p = res.get_probe(80)
    >>> for rule in p:
            f = rule.search_fingerprint(http_server)
            print(f)


Examples
--------

You can see some examples in this repo, at *examples/* folder


Contributing
============

Any collaboration is welcome!

There're many tasks to do.You can check the `Issues <https://github.com/cr0hn/nmap-fingerprinting/issues/>`_ and send us a Pull Request.

License
=======

This project is distributed under `BSD 3 <https://github.com/cr0hn/nmap-fingerprinting/LICENSE>`_



