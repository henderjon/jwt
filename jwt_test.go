package jwt

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
)

type tmp struct {
	Name  string `json:"nam,omitempty"`
	Email string `json:"eml,omitempty"`
	RegisteredClaims
}

func getPayload() *tmp {
	return &tmp{
		Name:  "John Paul Jones",
		Email: "jpj@ledzep.com",
		RegisteredClaims: RegisteredClaims{
			Subject: "a new jam",
			Expires: 1653073538,
			ID:      "7e3f16d2-b0d8-4248-85cb-db7856d4bfc4",
		},
	}
}

func TestMarshal(t *testing.T) {
	payload := getPayload()

	b, _ := json.Marshal(payload)
	expected := `{"nam":"John Paul Jones","eml":"jpj@ledzep.com","sub":"a new jam","exp":1653073538,"jti":"7e3f16d2-b0d8-4248-85cb-db7856d4bfc4"}`
	if diff := cmp.Diff(string(b), expected); diff != "" {
		t.Errorf("mashal error: (-got +want)\n%s", diff)
	}

}
