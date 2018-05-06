hmacsigner [![Build Status](https://secure.travis-ci.org/daaku/hmacsigner.png)](http://travis-ci.org/daaku/hmacsigner) [![GoDoc](https://godoc.org/github.com/daaku/hmacsigner?status.svg)](https://godoc.org/github.com/daaku/hmacsigner)
==========

Documentation: https://godoc.org/github.com/daaku/hmacsigner

Package hmacsigner provides signed blobs.

It is:
1. Not future proof.
1. Forces HMAC-SHA256 signatures.
1. Forces 8 byte nanosecond unix timestamp.
1. Forces 8 byte salt.
