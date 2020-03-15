=======
fe25519
=======

Native Python implementation of Ed25519 field elements and operations.

.. image:: https://badge.fury.io/py/fe25519.svg
   :target: https://badge.fury.io/py/fe25519
   :alt: PyPI version and link.

Purpose
-------
This library provides a native Python implementation of `Ed25519 <https://ed25519.cr.yp.to/>`_ field elements and a number of operations over them. The library makes it possible to fill gaps in prototype applications that may have specific limitations with respect to their operating environment or their ability to rely on dependencies.

The implementation is based upon and is compatible with the corresponding implementation of Ed25519 field elements used in `libsodium <https://github.com/jedisct1/libsodium>`_.

Package Installation and Usage
------------------------------
The package is available on PyPI::

    python -m pip install fe25519

The library can be imported in the usual ways::

    import fe25519
    from fe25519 import fe25519
