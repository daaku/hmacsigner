hmacsigner [![Build Status](https://secure.travis-ci.org/daaku/hmacsigner.png)](http://travis-ci.org/daaku/hmacsigner) [![GoDoc](https://godoc.org/github.com/daaku/hmacsigner?status.svg)](https://godoc.org/github.com/daaku/hmacsigner) [![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](blob/master/license)
==========

    import "github.com/daaku/hmacsigner"

Documentation: https://godoc.org/github.com/daaku/hmacsigner

Package hmacsigner provides signed blobs.

It is:
1. Not future proof.
1. Forces a Secret of at least 32 bytes.
1. Forces HMAC-SHA256 signatures.
1. Forces 8 byte nanosecond unix timestamp.
1. Forces 8 byte salt.
1. Forces URL safe Base64 encoding.

## Usage

```go
var (
	// ErrTooShort indicates the data to parse is too short to be valid.
	ErrTooShort = errors.New("hmacsigner: too short")

	// ErrInvalidEncoding indicates the encoding is invalid.
	ErrInvalidEncoding = errors.New("hmacsigner: invalid encoding")

	// ErrTimestampExpired indicates the timestamp has expired.
	ErrTimestampExpired = errors.New("hmacsigner: timestamp expired")

	// ErrSignatureMismatch indicates the signature is not as expected.
	ErrSignatureMismatch = errors.New("hmacsigner: signature mismatch")
)
```

#### type Signer

```go
type Signer struct {
	Secret []byte        // Secret must be at least 32 bytes.
	TTL    time.Duration // TTL must be non zero.
}
```

Signer handles generating and parsing signed data.

#### func (*Signer) Gen

```go
func (s *Signer) Gen(payload []byte) []byte
```
Gen returns the signed payload.

#### func (*Signer) Parse

```go
func (s *Signer) Parse(b []byte) ([]byte, error)
```
Parse returns the original payload. It verifies the signature and ensures the
TTL is respected.
