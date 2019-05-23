package jwt

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestSerializeHS384(t *testing.T) {
	payload := newHsClaims()
	signer := NewHMACSigner(HS384, []byte("random string"))

	token, err := Serialize(payload, signer)
	if err != nil {
		t.Error(err)
	}

	expected := `eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJuYW0iOiJKb2huIFBhdWwgSm9uZXMiLCJlbWwiOiJqcGpAbGVkemVwLmNvbSIsInN1YiI6ImEgbmV3IGphbSIsImV4cCI6MTY1MzA3MzUzOCwianRpIjoiN2UzZjE2ZDItYjBkOC00MjQ4LTg1Y2ItZGI3ODU2ZDRiZmM0In0.ee_NPBbUCvgT4hujOWp13jeNUiiiRZrRJaFok1p-SU6xXFz7pKEhG1yuA3bs_2Ah`
	if diff := cmp.Diff(token, expected); diff != "" {
		t.Errorf("serialize error: (-got +want)\n%s\n%s", err, diff)
	}
}

func TestUnserializeHS384(t *testing.T) {
	payload := newHsClaims()
	signer := NewHMACSigner(HS384, []byte("random string"))

	token, err := Serialize(payload, signer)
	if err != nil {
		t.Error(err)
	}

	m := &hsClaims{}
	if e := Unserialize(token, signer, m); e != nil {
		t.Errorf("unserialize error:\n%s", e)
	}

	if !m.Valid() {
		t.Error("VALIDATION!!")
	}

	if diff := cmp.Diff(m, payload); diff != "" {
		t.Errorf("serialize error: (-got +want)\n%s", diff)
	}
}
