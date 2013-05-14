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

Building the Anon-Pass server components
----------------------------------------

1. Install `pbc`: tested with version 0.5.12 but appears to work for
   0.5.13 as well.  `pbc` requires `libgmp`, on Ubuntu this is
   probably `libgmp3-dev`.

$ sudo apt-get install libgmp3-dev
$ wget http://crypto.stanford.edu/pbc/files/pbc-0.5.12.tar.gz
$ tar -xf pbc-0.5.12.tar.gz
$ cd ./pbc-0.5.12/
$ ./configure
$ make && sudo make install
$ cd ../

2. From there, you'll need polarssl to finish building libanonpass.

$ sudo apt-get install libpolarssl-dev

3. These are the pre-reqs for compiling `libanonpass`.  In addition,
   libhs shouldn't need any additional libraries.

$ cd libanonpass
$ make && sudo make install
$ cd ../libhs
$ make && sudo make install
$ cd ../

4. To compile the auth-server module, you'll need to add
   `anon-pass-module` to nginx.  Anon-Pass was tested with nginx
   version 1.2.3.  It needs a trivial patch to add an additional
   timeout for the gateway.

$ wget http://nginx.org/download/nginx-1.2.3.tar.gz
$ tar -xf nginx-1.2.3.tar.gz
$ cd nginx-1.2.3/
$ patch -p2 < ../nginx.diff
$ ./configure --with-http_ssl_module --add-module=../anon-pass-module
## You if you want the rewrite module for nginx, you will also need libpcre3-dev
# sudo apt-get install libpcre3-dev
## Otherwise you can disable this by adding --without-http_rewrite_module
$ make && sudo make install
$ cd ../

5. The last piece of the server is the networked hash table.  This has
   a pretty simple interface; however, we opted to make our own to
   integrate more of the logic with the hash table and reduce the
   number of round-trips necessary.

$ cd hash-server
$ make
$ cd ../
