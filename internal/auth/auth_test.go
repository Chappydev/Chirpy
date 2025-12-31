package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMakeJWT(t *testing.T) {
  secretString := "secret"
  timeToExpire := time.Millisecond * 200
  _, err := MakeJWT(uuid.New(), secretString, timeToExpire)
  if err != nil {
    t.Fatal(err)
  }
}

func TestValidateJWT(t *testing.T) {
  secretString := "secret"
  timeToExpire := time.Second * 1
  id := uuid.New()
  token, err := MakeJWT(id, secretString, timeToExpire)
  if err != nil {
    t.Fatal(err)
  }

  resultId, err := ValidateJWT(token, secretString)
  if err != nil {
    t.Fatal(err)
  } else if resultId.String() != id.String() {
    t.Errorf("resultId %s does not match the initial id %s", resultId.String(), id.String())
  }
}

func TestValidateExpiredJWT(t *testing.T) {
  secretString := "secret"
  timeToExpire := time.Millisecond * 500
  id := uuid.New()
  token, err := MakeJWT(id, secretString, timeToExpire)
  if err != nil {
    t.Fatal(err)
  }
  time.Sleep(time.Millisecond * 500)

  _, err = ValidateJWT(token, secretString)
  if err == nil {
    t.Error("Validation succeeded despite expected timeout")
  }
}

func TestValidateWrongSecretJWT(t *testing.T) {
  secretString := "secret"
  timeToExpire := time.Second * 1
  id := uuid.New()
  token, err := MakeJWT(id, secretString, timeToExpire)
  if err != nil {
    t.Fatal(err)
  }

  resultId, err := ValidateJWT(token, secretString)
  if err == nil && resultId.String() != id.String() {
    t.Error("Validation succeeded with the incorrect secret")
  }
}

func TestGetBearerToken(t *testing.T) {
  token := "tokenstring"
  bearer := "Bearer "

  headers := make(http.Header)
  headers.Set("Authorization", bearer + token)

  result, err := GetBearerToken(headers)
  if err != nil {
    t.Fatal(err)
  } else if result != token {
    t.Fatalf("Bearer token in result (%s) does not match the token in the header (%s)", result, token)
  }
}
