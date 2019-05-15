package jwt

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

type tmpHS256 struct {
	Name  string `json:"nam,omitempty"`
	Email string `json:"eml,omitempty"`
	Claims
}

func getPayloadHS256() *tmpHS256 {
	payload := &tmpHS256{
		Name:  "John Paul Jones",
		Email: "jpj@ledzep.com",
		Claims: Claims{
			Subject: "a new jam",
			Expires: 1653073538,
			ID:      "7e3f16d2-b0d8-4248-85cb-db7856d4bfc4",
		},
	}

	return payload
}

func TestSerializeHS256(t *testing.T) {
	payload := getPayloadHS256()
	signer := NewHMACSHA256([]byte("random string"))

	token := Serialize(payload, signer)
	expected := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW0iOiJKb2huIFBhdWwgSm9uZXMiLCJlbWwiOiJqcGpAbGVkemVwLmNvbSIsInN1YiI6ImEgbmV3IGphbSIsImV4cCI6MTY1MzA3MzUzOCwianRpIjoiN2UzZjE2ZDItYjBkOC00MjQ4LTg1Y2ItZGI3ODU2ZDRiZmM0In0.kAj7JvTsGHveCpA5UpcxSxsN2ECd_hY9cem_bp_e-Uc`
	if diff := cmp.Diff(token, expected); diff != "" {
		t.Errorf("serialize error: (-got +want)\n%s", diff)
	}
}

func TestUnserializeHS256(t *testing.T) {
	payload := getPayloadHS256()
	signer := NewHMACSHA256([]byte("random string"))

	token := Serialize(payload, signer)

	m := &tmpHS256{}
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
