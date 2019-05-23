package jwt

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

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
