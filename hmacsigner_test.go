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
		Secret: bytes.Repeat([]byte("a"), 32),
		TTL:    time.Since(givenIssue) + time.Hour,
		nowF:   func() time.Time { return givenIssue },
		saltF:  func(b []byte) { copy(b, givenSalt[:]) },
	}

	gen := signer.Gen(givenPayload)
	ensure.DeepEqual(t, string(gen),
		"AAAAAAAAAAAAAQIDBAUGB9jLMb8-Ey8EmPMUsZGwZrLydqsh-KhMZ0spLMAWMdknYUBiLmM")

	actualPayload, err := signer.Parse(gen)
	ensure.Nil(t, err)
	ensure.DeepEqual(t, actualPayload, givenPayload)
}

func TestErrors(t *testing.T) {
	givenIssue := time.Unix(0, time.Hour.Nanoseconds())
	signer := Signer{
		Secret: bytes.Repeat([]byte("a"), 32),
		TTL:    time.Since(givenIssue) + time.Hour,
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
			Name: "invalid encoding",
			Data: []byte(strings.Repeat("$", encHeaderLen)),
			Err:  ErrInvalidEncoding,
		},
		{
			Name: "ts expired",
			Data: []byte(strings.Repeat("A", encHeaderLen)),
			Err:  ErrTimestampExpired,
		},
		{
			Name: "invalid payload encoding",
			Data: []byte(validTS + strings.Repeat("A", encHeaderLen) + "$"),
			Err:  ErrInvalidEncoding,
		},
		{
			Name: "invalid signature",
			Data: []byte(validTS + strings.Repeat("A", encHeaderLen+20)),
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

func TestMinSecretLen(t *testing.T) {
	defer ensure.PanicDeepEqual(t, "key less than 32 bytes")
	(&Signer{}).Gen([]byte("foo"))
}

func TestNilPayload(t *testing.T) {
	signer := Signer{
		Secret: bytes.Repeat([]byte("a"), 32),
		TTL:    time.Hour,
	}
	out := signer.Gen(nil)
	orig, err := signer.Parse(out)
	ensure.Nil(t, err)
	ensure.True(t, orig == nil, orig)
}

func BenchmarkGen(b *testing.B) {
	givenPayload := []byte("a@b.c")
	signer := Signer{
		Secret: bytes.Repeat([]byte("a"), 32),
		TTL:    time.Hour,
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
		Secret: bytes.Repeat([]byte("a"), 32),
		TTL:    time.Hour,
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
