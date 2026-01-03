package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func HashPassword(password string) (string, error) {
  return argon2id.CreateHash(password, argon2id.DefaultParams)
}

func CheckPasswordHash(password, hash string) (bool, error) {
  return argon2id.ComparePasswordAndHash(password, hash)
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
  claims := &jwt.RegisteredClaims{
    Issuer: "chirpy",
    IssuedAt: jwt.NewNumericDate(time.Now().UTC()),
    ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiresIn)),
    Subject: userID.String(),
  }

  token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
  signedToken, err := token.SignedString([]byte(tokenSecret))
  if err != nil {
    return "", err
  }

  return signedToken, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
  token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{
    Issuer: "chirpy",
  }, func(t *jwt.Token) (any, error) {
    return []byte(tokenSecret), nil
  })
  if err != nil {
    return uuid.UUID{}, err
  }

  subjectString, err := token.Claims.GetSubject()
  if err != nil {
    return uuid.UUID{}, err
  }

  return uuid.Parse(subjectString)
}

func GetBearerToken(headers http.Header) (string, error) {
  authorization := headers.Get("Authorization")
  elements := strings.Split(authorization, " ")
  if elements[0] != "Bearer" {
    return "", errors.New("no bearer found in the headers")
  } 
  if len(elements) != 2 {
    return "", errors.New("too many arguments in bearer")
  }

  return elements[1], nil
}

func MakeRefreshToken() (string, error) {
  randomBytes := make([]byte, 32)
  rand.Read(randomBytes)
  randomString := hex.EncodeToString(randomBytes)
  return randomString, nil
}

func GetAPIKey(headers http.Header) (string, error) {
  authorization := headers.Get("Authorization")
  elements := strings.Split(authorization, " ")
  if elements[0] != "ApiKey" {
    return "", errors.New("no apikey found in the headers")
  } 
  if len(elements) != 2 {
    return "", errors.New("too many arguments in apikey")
  }

  return elements[1], nil
}
