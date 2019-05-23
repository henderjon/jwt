package jwt

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

type hsClaims struct {
	Name  string `json:"nam,omitempty"`
	Email string `json:"eml,omitempty"`
	RegisteredClaims
}

func newHsClaims() *hsClaims {
	return &hsClaims{
		Name:  "John Paul Jones",
		Email: "jpj@ledzep.com",
		RegisteredClaims: RegisteredClaims{
			Subject: "a new jam",
			Expires: 1653073538,
			ID:      "7e3f16d2-b0d8-4248-85cb-db7856d4bfc4",
		},
	}
}

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

func TestSerializeHS512(t *testing.T) {
	payload := newHsClaims()
	signer := NewHMACSigner(HS512, []byte("random string"))

	token, err := Serialize(payload, signer)
	if err != nil {
		t.Error(err)
	}

	expected := `eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJuYW0iOiJKb2huIFBhdWwgSm9uZXMiLCJlbWwiOiJqcGpAbGVkemVwLmNvbSIsInN1YiI6ImEgbmV3IGphbSIsImV4cCI6MTY1MzA3MzUzOCwianRpIjoiN2UzZjE2ZDItYjBkOC00MjQ4LTg1Y2ItZGI3ODU2ZDRiZmM0In0.bGKM6wtqaUq3ANJD6mFcrjW3WonA87GIRq_PTE9EDKe7EqzXkbb5-aiVcVk5m5O2JiIbx2wsEQ0YtpEVF-8G1Q`
	if diff := cmp.Diff(token, expected); diff != "" {
		t.Errorf("serialize error: (-got +want)\n%s", diff)
	}
}

func TestUnserializeHS512(t *testing.T) {
	payload := newHsClaims()
	signer := NewHMACSigner(HS512, []byte("random string"))

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
