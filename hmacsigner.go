// Package hmacsigner provides signed blobs.
//
// It:
//
// 1) Includes a version.
//
// 2) Includes 8 byte nanosecond unix timestamp.
//
// 3) Includes 8 byte salt.
//
// 4) Requires a Secret of at least 32 bytes.
//
// 5) Does not encrypt the payload.
//
// 6) Enforces HMAC-SHA256 signatures.
//
// 7) Outputs URL safe Base64 encoding.
package hmacsigner

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	version      = byte(1)
	versionLen   = 1
	saltLen      = 8
	issueLen     = 8
	sigLen       = sha256.Size
	sigOffset    = versionLen + issueLen + saltLen
	headerLen    = versionLen + issueLen + saltLen + sigLen
	minSecretLen = 32
)

var (
	// ErrTooShort indicates the data to parse is too short to be valid.
	ErrTooShort = errors.New("hmacsigner: too short")

	// ErrInvalidVersion indicates the version was invalid.
	ErrInvalidVersion = errors.New("hmacsigner: invalid version")

	// ErrInvalidEncoding indicates the encoding is invalid.
	ErrInvalidEncoding = errors.New("hmacsigner: invalid encoding")

	// ErrTimestampExpired indicates the timestamp has expired.
	ErrTimestampExpired = errors.New("hmacsigner: timestamp expired")

	// ErrSignatureMismatch indicates the signature is not as expected.
	ErrSignatureMismatch = errors.New("hmacsigner: signature mismatch")

	encHeaderLen = base64.RawURLEncoding.EncodedLen(headerLen)
)

// Signer handles generating and parsing signed data.
type Signer struct {
	Secret []byte        // Secret must be at least 32 bytes.
	TTL    time.Duration // TTL must be non zero.

	nowF  func() time.Time
	saltF func([]byte)
}

func (s *Signer) now() time.Time {
	if s.nowF == nil {
		return time.Now()
	}
	return s.nowF()
}

func (s *Signer) salt(b []byte) {
	if s.saltF == nil {
		if _, err := rand.Read(b); err != nil {
			panic(err)
		}
		return
	}
	s.saltF(b)
}

func (s *Signer) sign(
	header []byte,
	payload []byte,
	sig []byte,
) {
	mac := hmac.New(sha256.New, s.Secret)
	mac.Write(header)
	mac.Write(payload)
	mac.Sum(sig)
}

// Gen returns the signed payload.
func (s *Signer) Gen(payload []byte) []byte {
	if len(s.Secret) < minSecretLen {
		panic(fmt.Sprintf("key less than %v bytes", minSecretLen))
	}

	var header [headerLen]byte
	next := header[:]

	next[0] = version
	next = next[versionLen:]

	issue := s.now()
	binary.LittleEndian.PutUint64(next[:], uint64(issue.UnixNano()))
	next = next[issueLen:]

	s.salt(next[:saltLen])
	next = next[saltLen:]

	s.sign(header[:sigOffset], payload, next[:0])

	payloadEncLen := base64.RawURLEncoding.EncodedLen(len(payload))
	blob := make([]byte, payloadEncLen+encHeaderLen)
	base64.RawURLEncoding.Encode(blob, header[:])
	base64.RawURLEncoding.Encode(blob[encHeaderLen:], payload)
	return blob
}

// Parse returns the original payload. It verifies the signature and
// ensures the TTL is respected.
func (s *Signer) Parse(b []byte) ([]byte, error) {
	if len(b) < encHeaderLen {
		return nil, ErrTooShort
	}

	var header [headerLen]byte
	next := header[:]
	_, err := base64.RawURLEncoding.Decode(next, b[:encHeaderLen])
	if err != nil {
		return nil, ErrInvalidEncoding
	}
	b = b[encHeaderLen:]

	if next[0] != version {
		return nil, ErrInvalidVersion
	}
	next = next[versionLen:]

	ts := int64(binary.LittleEndian.Uint64(next[:issueLen]))
	issue := time.Unix(0, ts)
	if issue.Add(s.TTL).Before(time.Now()) {
		return nil, ErrTimestampExpired
	}
	next = next[issueLen:]

	var payload []byte
	if payloadLen := len(b); payloadLen > 0 {
		payload = make([]byte, base64.RawURLEncoding.DecodedLen(payloadLen))
		n, err := base64.RawURLEncoding.Decode(payload, b)
		if err != nil {
			return nil, ErrInvalidEncoding
		}
		payload = payload[:n]
	}

	var expectedSig [sha256.Size]byte
	s.sign(header[:sigOffset], payload, expectedSig[:0])
	if !hmac.Equal(expectedSig[:], header[sigOffset:]) {
		return nil, ErrSignatureMismatch
	}
	return payload, nil
}
