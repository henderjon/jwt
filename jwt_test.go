package jwt

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

type tmp struct {
	Name  string `json:"nam,omitempty"`
	Email string `json:"eml,omitempty"`
	Claims
}

func TestBlah(t *testing.T) {
	var expected string
	// our secret secret
	signer := NewHMACSHA256([]byte("random string"))

	payload := &tmp{
		Name:  "John Paul Jones",
		Email: "jpj@ledzep.com",
		Claims: Claims{
			Subject: "a new jam",
			Expires: 1653073538,
			ID:      "7e3f16d2-b0d8-4248-85cb-db7856d4bfc4",
		},
	}

	b, _ := json.Marshal(payload)
	expected = `{"nam":"John Paul Jones","eml":"jpj@ledzep.com","sub":"a new jam","exp":1653073538,"jti":"7e3f16d2-b0d8-4248-85cb-db7856d4bfc4"}`
	if diff := cmp.Diff(string(b), expected); diff != "" {
		t.Errorf("mashal error: (-got +want)\n%s", diff)
	}

	token := Serialize(payload, signer)
	expected = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW0iOiJKb2huIFBhdWwgSm9uZXMiLCJlbWwiOiJqcGpAbGVkemVwLmNvbSIsInN1YiI6ImEgbmV3IGphbSIsImV4cCI6MTY1MzA3MzUzOCwianRpIjoiN2UzZjE2ZDItYjBkOC00MjQ4LTg1Y2ItZGI3ODU2ZDRiZmM0In0.kAj7JvTsGHveCpA5UpcxSxsN2ECd_hY9cem_bp_e-Uc`
	if diff := cmp.Diff(token, expected); diff != "" {
		t.Errorf("serialize error: (-got +want)\n%s", diff)
	}

	m := &tmp{}
	e := Unserialize(token, signer, m)
	if e != nil {
		t.Errorf("unserialize error:\n%s", e)
	}

	if !m.IsActive(time.Now().UTC().Unix()) {
		t.Error("token is not valid yet")
	}

	if m.IsExpired(time.Now().UTC().Unix()) {
		t.Error("EXPIRED!!")
	}

	if diff := cmp.Diff(m, payload); diff != "" {
		t.Errorf("serialize error: (-got +want)\n%s", diff)
	}

}
