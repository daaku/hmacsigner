// Package hmacsigner is a simple hmac only timestamped signed blob. It is not
// futured proofed, it forces decisions on you like using sha256.
package hmacsigner

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"time"
)

const (
	saltLen    = 8
	encTsLen   = 11
	encSaltLen = 11
	encSigLen  = 43
	encLen     = encTsLen + encSaltLen + encSigLen
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
)

// Signer handles generating and parsing signed data.
type Signer struct {
	Key []byte
	TTL time.Duration

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
	payload []byte,
	salt [saltLen]byte,
	issue time.Time,
) []byte {
	var scratch [8]byte
	binary.LittleEndian.PutUint64(scratch[:], uint64(issue.UnixNano()))

	mac := hmac.New(sha256.New, s.Key)
	mac.Write(scratch[:])
	mac.Write(salt[:])
	mac.Write(payload)
	return mac.Sum(nil)
}

// Gen returns the signed payload.
func (s *Signer) Gen(payload []byte) []byte {
	issue := s.now()
	payloadEncLen := base64.RawURLEncoding.EncodedLen(len(payload))
	blob := make([]byte, payloadEncLen+encLen)
	var scratch [8]byte

	binary.LittleEndian.PutUint64(scratch[:], uint64(issue.UnixNano()))
	base64.RawURLEncoding.Encode(blob, scratch[:])

	s.salt(scratch[:])
	base64.RawURLEncoding.Encode(blob[encTsLen:], scratch[:])

	sig := s.sign(payload, scratch, issue)
	base64.RawURLEncoding.Encode(blob[encTsLen+encSaltLen:], sig)

	base64.RawURLEncoding.Encode(blob[encLen:], payload)
	return blob
}

// Parse returns the original payload. It verifies the signature and
// ensures the TTL is respected.
func (s *Signer) Parse(b []byte) ([]byte, error) {
	if len(b) < encLen+1 {
		return nil, ErrTooShort
	}

	var scratch [8]byte
	_, err := base64.RawURLEncoding.Decode(scratch[:], b[:encTsLen])
	if err != nil {
		return nil, ErrInvalidEncoding
	}
	ts := int64(binary.LittleEndian.Uint64(scratch[:]))
	issue := time.Unix(0, ts)
	if issue.Add(s.TTL).Before(time.Now()) {
		return nil, ErrTimestampExpired
	}

	_, err = base64.RawURLEncoding.Decode(
		scratch[:], b[encTsLen:encTsLen+encSaltLen])
	if err != nil {
		return nil, ErrInvalidEncoding
	}

	var sig [sha256.Size]byte
	_, err = base64.RawURLEncoding.Decode(
		sig[:], b[encTsLen+encSaltLen:encLen])
	if err != nil {
		return nil, ErrInvalidEncoding
	}

	payload := make([]byte, base64.RawURLEncoding.DecodedLen(len(b)-encLen))
	n, err := base64.RawURLEncoding.Decode(payload, b[encLen:])
	if err != nil {
		return nil, ErrInvalidEncoding
	}
	payload = payload[:n]

	if !hmac.Equal(s.sign(payload, scratch, issue), sig[:]) {
		return nil, ErrSignatureMismatch
	}
	return payload, nil
}
