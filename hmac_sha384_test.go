package jwt

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

type tmpHS384 struct {
	Name  string `json:"nam,omitempty"`
	Email string `json:"eml,omitempty"`
	Claims
}

func getPayloadHS384() *tmpHS384 {
	payload := &tmpHS384{
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

func TestSerializeHS384(t *testing.T) {
	payload := getPayloadHS384()
	signer := NewHMACSHA384([]byte("random string"))

	token := Serialize(payload, signer)
	expected := `eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJuYW0iOiJKb2huIFBhdWwgSm9uZXMiLCJlbWwiOiJqcGpAbGVkemVwLmNvbSIsInN1YiI6ImEgbmV3IGphbSIsImV4cCI6MTY1MzA3MzUzOCwianRpIjoiN2UzZjE2ZDItYjBkOC00MjQ4LTg1Y2ItZGI3ODU2ZDRiZmM0In0.ee_NPBbUCvgT4hujOWp13jeNUiiiRZrRJaFok1p-SU6xXFz7pKEhG1yuA3bs_2Ah`
	if diff := cmp.Diff(token, expected); diff != "" {
		t.Errorf("serialize error: (-got +want)\n%s", diff)
	}
}

func TestUnserializeHS384(t *testing.T) {
	payload := getPayloadHS384()
	signer := NewHMACSHA384([]byte("random string"))

	token := Serialize(payload, signer)

	m := &tmpHS384{}
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
