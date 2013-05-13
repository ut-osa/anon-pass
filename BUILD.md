NOTE: The compilation procedure is not yet fully documented.
=====

Building Anon-Pass
==================

Anon-Pass in its current incarnation has a number of external library
dependencies:

1. [The GNU Multiple Precision Arithmetic Library (libgmp):http://gmplib.org/]
2. [The Pairing-Based Cryptographic Library (libpbc):http://crypto.stanford.edu/pbc/]
3. [OpenSSL:http://www.openssl.org/]
4. [PolarSSL:https://polarssl.org/]

We are in the process of removing the PolarSSL dependency; however, it
is useful for packaging the necessary cryptographic operations into
client implementations.
