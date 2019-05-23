package jwt

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestSerializeSignHS256(t *testing.T) {
	payload := newHsClaims()
	signer := NewHMACSigner(HS256, []byte("random string"))

	token, err := Serialize(payload, signer)
	if err != nil {
		t.Error(err)
	}

	expected := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW0iOiJKb2huIFBhdWwgSm9uZXMiLCJlbWwiOiJqcGpAbGVkemVwLmNvbSIsInN1YiI6ImEgbmV3IGphbSIsImV4cCI6MTY1MzA3MzUzOCwianRpIjoiN2UzZjE2ZDItYjBkOC00MjQ4LTg1Y2ItZGI3ODU2ZDRiZmM0In0.kAj7JvTsGHveCpA5UpcxSxsN2ECd_hY9cem_bp_e-Uc`
	if diff := cmp.Diff(token, expected); diff != "" {
		t.Errorf("serialize error: (-got +want)\n%s", diff)
	}
}

func TestUnserializeSignHS256(t *testing.T) {
	payload := newHsClaims()
	signer := NewHMACSigner(HS256, []byte("random string"))

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
