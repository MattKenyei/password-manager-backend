package domain

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID                 uuid.UUID
	Email              string
	AuthVerifier       []byte
	AuthSalt           []byte
	EncSalt            []byte
	KDFParams          []byte
	WrappedAccountKey  []byte
	KeyGeneration      int
	CreatedAt          time.Time
	UpdatedAt          time.Time
}