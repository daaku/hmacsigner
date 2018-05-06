package hmacsigner

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/daaku/ensure"
)

func TestSigner(t *testing.T) {
	givenPayload := []byte("a@b.c")
	givenIssue := time.Unix(0, 0)
	signer := Signer{
		Key: []byte("1234567890"),
		TTL: time.Now().Sub(givenIssue) + time.Hour,
	}

	expectedSig := []byte{
		0xAF, 0x1E, 0x9F, 0x6F, 0x5C, 0x82, 0xE1, 0xE6,
		0x0C, 0x90, 0x5F, 0xE0, 0x8D, 0x37, 0x7A, 0x93,
		0xD1, 0x65, 0x24, 0xA4, 0x9C, 0x5A, 0xA6, 0x86,
		0xD3, 0xAE, 0x9E, 0x9D, 0xC1, 0xED, 0x27, 0x4B,
	}
	ensure.DeepEqual(t, signer.Sign(givenPayload, givenIssue), expectedSig)

	gen := signer.Gen(givenPayload, givenIssue)
	ensure.DeepEqual(t, string(gen),
		"AAAAAAAAAAArx6fb1yC4eYMkF_gjTd6k9FlJKScWqaG066encHtJ0sYUBiLmM")

	actualPayload, actualIssue, err := signer.Parse(gen)
	ensure.Nil(t, err)
	ensure.DeepEqual(t, actualPayload, givenPayload)
	ensure.DeepEqual(t, actualIssue, givenIssue)
}

func TestErrors(t *testing.T) {
	givenIssue := time.Unix(0, time.Hour.Nanoseconds())
	signer := Signer{
		Key: []byte("1234567890"),
		TTL: time.Now().Sub(givenIssue) + time.Hour,
	}

	var ts [8]byte
	binary.LittleEndian.PutUint64(ts[:], uint64(givenIssue.UnixNano()))
	validTS := base64.RawURLEncoding.EncodeToString(ts[:])

	cases := []struct {
		Data []byte
		Err  error
	}{
		{
			Data: nil,
			Err:  ErrTooShort,
		},
		{
			Data: []byte(strings.Repeat("$", encLen+10)),
			Err:  ErrTimestampInvalid,
		},
		{
			Data: []byte("AAAAAAAAAAA" + strings.Repeat("$", encLen+10)),
			Err:  ErrTimestampExpired,
		},
		{
			Data: []byte(validTS + strings.Repeat("$", encLen+10)),
			Err:  ErrSignatureInvalid,
		},
		{
			Data: []byte(validTS + strings.Repeat("A", encSigLen) + "$"),
			Err:  ErrPayloadInvalid,
		},
		{
			Data: []byte(validTS + strings.Repeat("A", encSigLen+10)),
			Err:  ErrSignatureMismatch,
		},
	}

	for _, c := range cases {
		_, _, err := signer.Parse(c.Data)
		ensure.DeepEqual(t, err, c.Err)
	}
}
