package token

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Issuer struct {
	secret []byte
	ttl    time.Duration
}

func NewIssuer(secret []byte, ttl time.Duration) *Issuer {
	return &Issuer{secret: secret, ttl: ttl}
}

func (i *Issuer) Issue(userID, deviceID uuid.UUID) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": userID.String(),
		"did": deviceID.String(),
		"iat": now.Unix(),
		"exp": now.Add(i.ttl).Unix(),
		"iss": "password-manager",
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := t.SignedString(i.secret)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return signed, nil
}

func (i *Issuer) Parse(tokenStr string) (uuid.UUID, uuid.UUID, error) {
	t, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return i.secret, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("parse token: %w", err)
	}

	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok || !t.Valid {
		return uuid.Nil, uuid.Nil, errors.New("invalid token claims")
	}

	subStr, _ := claims["sub"].(string)
	didStr, _ := claims["did"].(string)

	userID, err := uuid.Parse(subStr)
	if err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("invalid sub claim: %w", err)
	}
	deviceID, err := uuid.Parse(didStr)
	if err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("invalid did claim: %w", err)
	}

	return userID, deviceID, nil
}
