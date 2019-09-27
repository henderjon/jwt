package jwt

import (
	"os"
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
		RegisteredClaims: RegisteredClaims{
			Subject:        "a new jam",
			ExpirationTime: 1653073538,
			JWTID:          "7e3f16d2-b0d8-4248-85cb-db7856d4bfc4",
		},
		Name:  "John Paul Jones",
		Email: "jpj@ledzep.com",
	}
}

func TestSerializeSignHS256(t *testing.T) {
	payload := newHsClaims()
	signer := NewHMACSigner(HS256, []byte("random string"))

	token, err := Serialize(payload, signer)
	if err != nil {
		t.Error(err)
	}

	expected := `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW0iOiJKb2huIFBhdWwgSm9uZXMiLCJlbWwiOiJqcGpAbGVkemVwLmNvbSIsImp0aSI6IjdlM2YxNmQyLWIwZDgtNDI0OC04NWNiLWRiNzg1NmQ0YmZjNCIsImV4cCI6MTY1MzA3MzUzOCwic3ViIjoiYSBuZXcgamFtIn0.GMsqTvA5SQHR6rCD5QFnW2nipAETlNEv09oXXLhZqqM`
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

	expected := `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJuYW0iOiJKb2huIFBhdWwgSm9uZXMiLCJlbWwiOiJqcGpAbGVkemVwLmNvbSIsImp0aSI6IjdlM2YxNmQyLWIwZDgtNDI0OC04NWNiLWRiNzg1NmQ0YmZjNCIsImV4cCI6MTY1MzA3MzUzOCwic3ViIjoiYSBuZXcgamFtIn0.9sGryaXKQ7ymTEok8lvzKBFtQLk14xvdJzNtB8LyxdZweLn6r94m8qJQXsfxIsnD`
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

	expected := `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJuYW0iOiJKb2huIFBhdWwgSm9uZXMiLCJlbWwiOiJqcGpAbGVkemVwLmNvbSIsImp0aSI6IjdlM2YxNmQyLWIwZDgtNDI0OC04NWNiLWRiNzg1NmQ0YmZjNCIsImV4cCI6MTY1MzA3MzUzOCwic3ViIjoiYSBuZXcgamFtIn0.TmOdxqwZsjN6AbijFH0EaohJ9RGcS-ZaypmW4GSZ5qUf3Q9zaA6LSUycrfCscll7rNQOK075dkj7goxUaZxqWQ`
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

type myonClaims struct {
	RegisteredClaims
	UserID      int      `json:"uid,omitempty"`
	UserRoleID  int      `json:"urid,omitempty"`
	UserGradeID int      `json:"ugid,omitempty"`
	AccountID   int      `json:"aid,omitempty"`
	BuildingID  int      `json:"bid,omitempty"`
	Permissions []int    `json:"perms,omitempty"`
	Lang        []string `json:"lng,omitempty"`
	LoggedIn    bool     `json:"loggedIn,omitempty"`
}

func TestHS256Verify(t *testing.T) {
	// payload := `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJodHRwczpcL1wvd3d3Lm15b24uY29tIiwiaXNzIjoiaHR0cHM6XC9cL3d3dy5teW9uLmNvbSIsImp0aSI6ImUwOWFiMDhmLTJkZmEtNGU0MS05YzhiLWVlYmRmMDhiZWYwYyIsImlhdCI6MTU2MjY3ODA0MywiZXhwIjoxNTYyNjc5MzYzLCJ1aWQiOjIwNTA4NDAsInVyaWQiOjIsInVnaWQiOjgsImFpZCI6NDA1Njc1LCJiaWQiOjQwNTY3NiwicGVybXMiOlsxLDIsNCw1LDYsOCwxOSwzMSw3NCwxMzIsMTM3LDEzOCwxNDMsMTQ3LDE2NSwxNjYsMTc2LDE3OCwxNzldLCJsbmciOlsiZW5fdXMiXSwibG9nZ2VkSW4iOnRydWV9.O_EJseZVWT__aWer3dqA6L7vYUDrefk5opXijHw6Ur0`
	payload := `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJodHRwczovL3d3dy5teW9uLmNvbSIsImlzcyI6Imh0dHBzOi8vd3d3Lm15b24uY29tIiwianRpIjoiZTA5YWIwOGYtMmRmYS00ZTQxLTljOGItZWViZGYwOGJlZjBjIiwiaWF0IjoxNTYyNjc4MDQzLCJleHAiOjE1NjI2NzkzNjMsInVpZCI6MjA1MDg0MCwidXJpZCI6MiwidWdpZCI6OCwiYWlkIjo0MDU2NzUsImJpZCI6NDA1Njc2LCJwZXJtcyI6WzEsMiw0LDUsNiw4LDE5LDMxLDc0LDEzMiwxMzcsMTM4LDE0MywxNDcsMTY1LDE2NiwxNzYsMTc4LDE3OV0sImxuZyI6WyJlbl91cyJdLCJsb2dnZWRJbiI6dHJ1ZX0.VbyIeBHa6CsQIk4K5y2K49DRBz43PKzTI88JgzN8PP0`
	signer := NewHMACSigner(HS256, []byte(os.Getenv("TESTSALT")))

	m := &myonClaims{}
	err := Unserialize(payload, signer, m)
	if err != nil {
		t.Error(err)
	}
}

func TestHS256Verify2(t *testing.T) {
	// payload := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1dWlkIjoiMWFiYTA1MWQtZmFjNS00YWM2LWI4NGQtNTNjMjk3NWFiZDFkIiwibGFhIjoxNTYyNjg4NTYwLCJ0YWwiOjE3OCwiZXhwIjoxNTYyNzk2NTYwLCJpYXQiOjE1NjI2ODQzMTIsImp0aSI6ImE4OTdiYzUyLWU3ZjMtNGI1NC05OGFhLTdmMzIzZDVhNzAwNyJ9.s1ncQBuamfBFDTIZzljnH42TuqmlGhxqTdfdQSujJow`
	payload := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1dWlkIjoiMWFiYTA1MWQtZmFjNS00YWM2LWI4NGQtNTNjMjk3NWFiZDFkIiwibGFhIjoxNTYyNjg4NTYwLCJ0YWwiOjE3OCwiZXhwIjoxNTYyNzk2NTYwLCJpYXQiOjE1NjI2ODQzMTIsImp0aSI6ImE4OTdiYzUyLWU3ZjMtNGI1NC05OGFhLTdmMzIzZDVhNzAwNyJ9.D_554zxvAjm0dRkC6WW0YelYlzdCgTJJ_DJcgKspl2g`
	signer := NewHMACSigner(HS256, []byte(os.Getenv("TESTSALT")))

	m := &myonClaims{}
	err := Unserialize(payload, signer, m)
	if err != nil {
		t.Error(err)
	}
}
