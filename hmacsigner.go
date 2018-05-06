// Package hmacsigner is a simple hmac only timestamped signed blob. It is not
// futured proofed, it forces decisions on you like using sha256.
package hmacsigner

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"strconv"
	"time"
)

const (
	encTsLen  = 11
	encSigLen = 43
	encLen    = encTsLen + encSigLen
)

var (
	// ErrTooShort indicates the data to parse is too short to be valid.
	ErrTooShort = errors.New("hmacsigner: too short")

	// ErrTimestampInvalid indicates the timestamp encoding is invalid.
	ErrTimestampInvalid = errors.New("hmacsigner: invalid timestamp encoding")

	// ErrTimestampExpired indicates the timestamp has expired.
	ErrTimestampExpired = errors.New("hmacsigner: timestamp expired")

	// ErrSignatureInvalid indicates the signature encoding is invalid.
	ErrSignatureInvalid = errors.New("hmacsigner: invalid signature encoding")

	// ErrPayloadInvalid indicates the payload encoding is invalid.
	ErrPayloadInvalid = errors.New("hmacsigner: invalid payload encoding")

	// ErrSignatureMismatch indicates the signature is not as expected.
	ErrSignatureMismatch = errors.New("hmacsigner: signature mismatch")
)

// Signer handles signing, generating and parsing data.
type Signer struct {
	Key []byte
	TTL time.Duration

	nowF func() time.Time
}

func (s *Signer) now() time.Time {
	if s.nowF == nil {
		return time.Now()
	}
	return s.nowF()
}

func (s *Signer) sign(payload []byte, issue time.Time) []byte {
	mac := hmac.New(sha256.New, s.Key)
	mac.Write(payload)
	io.WriteString(mac, strconv.FormatInt(issue.UnixNano(), 10))
	return mac.Sum(nil)
}

// Gen returns the signed and timestamped payload.
func (s *Signer) Gen(payload []byte) []byte {
	issue := s.now()
	payloadEncLen := base64.RawURLEncoding.EncodedLen(len(payload))
	blob := make([]byte, payloadEncLen+encLen)
	var ts [8]byte
	binary.LittleEndian.PutUint64(ts[:], uint64(issue.UnixNano()))
	base64.RawURLEncoding.Encode(blob, ts[:])
	base64.RawURLEncoding.Encode(blob[encTsLen:], s.sign(payload, issue))
	base64.RawURLEncoding.Encode(blob[encLen:], payload)
	return blob
}

// Parse returns the original payload. It verifies the signature and
// ensures the TTL is respected.
func (s *Signer) Parse(b []byte) ([]byte, error) {
	if len(b) < encLen+1 {
		return nil, ErrTooShort
	}

	var tsB [8]byte
	_, err := base64.RawURLEncoding.Decode(tsB[:], b[:encTsLen])
	if err != nil {
		return nil, ErrTimestampInvalid
	}
	ts := int64(binary.LittleEndian.Uint64(tsB[:]))
	issue := time.Unix(0, ts)
	if issue.Add(s.TTL).Before(time.Now()) {
		return nil, ErrTimestampExpired
	}

	var sig [sha256.Size]byte
	_, err = base64.RawURLEncoding.Decode(sig[:], b[encTsLen:encLen])
	if err != nil {
		return nil, ErrSignatureInvalid
	}

	payload := make([]byte, base64.RawURLEncoding.DecodedLen(len(b)-encLen))
	n, err := base64.RawURLEncoding.Decode(payload, b[encLen:])
	if err != nil {
		return nil, ErrPayloadInvalid
	}
	payload = payload[:n]

	if !hmac.Equal(s.sign(payload, issue), sig[:]) {
		return nil, ErrSignatureMismatch
	}
	return payload, nil
}
