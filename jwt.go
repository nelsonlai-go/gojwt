package gojwt

import (
	"time"

	"github.com/golang-jwt/jwt"
)

type JWT struct {
	secret string
	data   map[string]any
}

func New(secret string) *JWT {
	j := &JWT{
		secret: secret,
		data:   make(map[string]any),
	}
	return j
}

func NewFromToken(token string, secret string) (*JWT, error) {
	j := New(secret)

	claims, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}

	mapClaims := claims.Claims.(jwt.MapClaims)
	for k, v := range mapClaims {
		j.Set(k, v)
	}

	return j, nil
}

func (j *JWT) Set(key string, value any) {
	j.data[key] = value
}

func (j *JWT) Get(key string) any {
	return j.data[key]
}

func (j *JWT) Token(duration time.Duration) (string, error) {
	claims := jwt.MapClaims{}
	claims["exp"] = time.Now().Add(duration).Unix()
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(j.secret))
}
