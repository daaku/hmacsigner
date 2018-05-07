// Package hmacsigner provides signed blobs.
//
// It is:
//
// 1) Not future proof.
//
// 2) Forces a Secret of at least 32 bytes.
//
// 3) Forces HMAC-SHA256 signatures.
//
// 4) Forces 8 byte nanosecond unix timestamp.
//
// 5) Forces 8 byte salt.
//
// 6) Forces URL safe Base64 encoding.
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
	saltLen      = 8
	issueLen     = 8
	sigLen       = sha256.Size
	headerLen    = issueLen + saltLen + sigLen
	minSecretLen = 32
)

var (
	// ErrTooShort indicates the data to parse is too short to be valid.
	ErrTooShort = errors.New("hmacsigner: too short")

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
	issue := s.now()
	binary.LittleEndian.PutUint64(header[:], uint64(issue.UnixNano()))
	s.salt(header[issueLen : issueLen+saltLen])
	s.sign(header[:issueLen+saltLen], payload, header[:issueLen+saltLen])

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
	_, err := base64.RawURLEncoding.Decode(header[:], b[:encHeaderLen])
	if err != nil {
		return nil, ErrInvalidEncoding
	}
	b = b[encHeaderLen:]

	ts := int64(binary.LittleEndian.Uint64(header[:issueLen]))
	issue := time.Unix(0, ts)
	if issue.Add(s.TTL).Before(time.Now()) {
		return nil, ErrTimestampExpired
	}

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
	s.sign(header[:issueLen+saltLen], payload, expectedSig[:0])
	if !hmac.Equal(expectedSig[:], header[issueLen+saltLen:]) {
		return nil, ErrSignatureMismatch
	}
	return payload, nil
}
