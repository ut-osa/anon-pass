NOTE: The compilation procedure is not yet fully documented.
=====

Anon-Pass
=========

Anon-Pass is a practical cryptographic anonymous subscription scheme.
Combined with a proof-of-concept integration, it can scale to
thousands of concurrent users.  See
http://zweb.cs.utexas.edu/users/osa/anon-pass/ for more details.

Library Dependencies
====================

1. [The GNU Multiple Precision Arithmetic Library (libgmp):http://gmplib.org/]
2. [The Pairing-Based Cryptographic Library (libpbc):http://crypto.stanford.edu/pbc/]
3. [OpenSSL:http://www.openssl.org/]
4. [PolarSSL:https://polarssl.org/]

Introduction
============

Anon-Pass implements a cryptographic protocol that tries to guarantee
both admission control and anonymity to the user.  Either one of these
is easy to achieve (force every user to register a unique identifier,
or give every user free entry), but because these goals are at odds
with each other, both at the same time is difficult.

Anon-Pass takes a pragmatic approach to this problem and forces a few
trade-offs in pursuit of an anonymous subscription scheme.  We use the
concept of a linkable window (called in epoch in our paper) to define
when shared credentials can be detected.  However, to aid in user
flexibility, we add an explicit lightweight protocol to link (or
re-up, as termed in the paper) users across an epoch boundary.

Architecture
============

Anon-Pass is split into three logical entities: the client, the gateway,
and the authentication service.
