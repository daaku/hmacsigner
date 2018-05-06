package hmacsigner

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/daaku/ensure"
)

func TestSigner(t *testing.T) {
	givenPayload := []byte("a@b.c")
	givenIssue := time.Unix(0, 0)
	givenSalt := [saltLen]byte{0, 1, 2, 3, 4, 5, 6, 7}
	signer := Signer{
		Key:   []byte("1234567890"),
		TTL:   time.Since(givenIssue) + time.Hour,
		nowF:  func() time.Time { return givenIssue },
		saltF: func(b []byte) { copy(b, givenSalt[:]) },
	}

	expectedSig := []byte{
		0xF4, 0xAB, 0x56, 0xF9, 0x73, 0x88, 0x18, 0xD7,
		0x3F, 0x72, 0x03, 0xDD, 0x39, 0x56, 0xDF, 0xE5,
		0x9C, 0x08, 0xAE, 0xAE, 0xF9, 0x8C, 0x49, 0x80,
		0x11, 0x6D, 0xFD, 0x48, 0xB5, 0xEF, 0x52, 0x5D,
	}
	ensure.DeepEqual(t,
		signer.sign(givenPayload, givenSalt, givenIssue), expectedSig)

	gen := signer.Gen(givenPayload)
	ensure.DeepEqual(t, string(gen),
		"AAAAAAAAAAAAAECAwQFBgc9KtW-XOIGNc_cgPdOVbf5ZwIrq75jEmAEW39SLXvUl0YUBiLmM")

	actualPayload, err := signer.Parse(gen)
	ensure.Nil(t, err)
	ensure.DeepEqual(t, actualPayload, givenPayload)
}

func TestErrors(t *testing.T) {
	givenIssue := time.Unix(0, time.Hour.Nanoseconds())
	signer := Signer{
		Key: []byte("1234567890"),
		TTL: time.Since(givenIssue) + time.Hour,
	}

	var ts [8]byte
	binary.LittleEndian.PutUint64(ts[:], uint64(givenIssue.UnixNano()))
	validTS := base64.RawURLEncoding.EncodeToString(ts[:])

	cases := []struct {
		Name string
		Data []byte
		Err  error
	}{
		{
			Name: "nil data",
			Data: nil,
			Err:  ErrTooShort,
		},
		{
			Name: "invalid ts encoding",
			Data: []byte(strings.Repeat("$", encLen+10)),
			Err:  ErrInvalidEncoding,
		},
		{
			Name: "ts expired",
			Data: []byte("AAAAAAAAAAA" + strings.Repeat("$", encLen+10)),
			Err:  ErrTimestampExpired,
		},
		{
			Name: "invalid salt encoding",
			Data: []byte(validTS + strings.Repeat("$", encLen+10)),
			Err:  ErrInvalidEncoding,
		},
		{
			Name: "invalid sig encoding",
			Data: []byte(validTS +
				strings.Repeat("A", encSaltLen) + strings.Repeat("$", encLen+10)),
			Err: ErrInvalidEncoding,
		},
		{
			Name: "invalid payload encoding",
			Data: []byte(validTS + strings.Repeat("A", encSigLen+encSigLen) + "$"),
			Err:  ErrInvalidEncoding,
		},
		{
			Name: "invalid signature",
			Data: []byte(validTS + strings.Repeat("A", encLen+20)),
			Err:  ErrSignatureMismatch,
		},
	}

	for _, c := range cases {
		_, err := signer.Parse(c.Data)
		ensure.DeepEqual(t, err, c.Err, c.Name)
	}
}

func TestTimeNowDefault(t *testing.T) {
	ensure.NotNil(t, (&Signer{}).now())
}

func TestSaltDefault(t *testing.T) {
	var out [8]byte
	(&Signer{}).salt(out[:])
}

func BenchmarkGen(b *testing.B) {
	givenPayload := []byte("a@b.c")
	signer := Signer{
		Key: []byte("1234567890"),
		TTL: time.Hour,
	}
	expectedSuffix := []byte("LmM")

	for i := 0; i < b.N; i++ {
		gen := signer.Gen(givenPayload)
		if !bytes.HasSuffix(gen, expectedSuffix) {
			b.Fatal("did not find expected suffix", fmt.Sprintf("%s", gen))
		}
	}
}

func BenchmarkParse(b *testing.B) {
	givenPayload := []byte("a@b.c")
	signer := Signer{
		Key: []byte("1234567890"),
		TTL: time.Hour,
	}
	data := signer.Gen(givenPayload)

	for i := 0; i < b.N; i++ {
		actual, err := signer.Parse(data)
		if err != nil {
			b.Fatal("parse error", err)
		}
		if !bytes.Equal(actual, givenPayload) {
			b.Fatal("actual not as expected", actual)
		}
	}
}
