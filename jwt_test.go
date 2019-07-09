package jwt

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
)

type tmp struct {
	RegisteredClaims
	Name  string `json:"nam,omitempty"`
	Email string `json:"eml,omitempty"`
}

func getPayload() *tmp {
	return &tmp{
		Name:  "John Paul Jones",
		Email: "jpj@ledzep.com",
		RegisteredClaims: RegisteredClaims{
			Subject:        "a new jam",
			ExpirationTime: 1653073538,
			JWTID:          "7e3f16d2-b0d8-4248-85cb-db7856d4bfc4",
		},
	}
}

func TestMarshal(t *testing.T) {
	payload := getPayload()

	b, _ := json.Marshal(payload)
	expected := `{"jti":"7e3f16d2-b0d8-4248-85cb-db7856d4bfc4","exp":1653073538,"sub":"a new jam","nam":"John Paul Jones","eml":"jpj@ledzep.com"}`
	if diff := cmp.Diff(string(b), expected); diff != "" {
		t.Errorf("mashal error: (-got +want)\n%s", diff)
	}

}
