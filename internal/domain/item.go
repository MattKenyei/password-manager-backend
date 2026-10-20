package domain

import (
	"time"

	"github.com/google/uuid"
)

type Item struct {
	ID             uuid.UUID
	UserID         uuid.UUID
	EncryptedBlob  []byte
	Version        int64
	GlobalRevision int64
	Deleted        bool
	UpdatedAt      time.Time
	CreatedAt      time.Time
}

type Change struct {
	ID            uuid.UUID
	EncryptedBlob []byte
	BaseVersion   int64
	Deleted       bool
}

type Conflict struct {
	ID            uuid.UUID
	ServerVersion int64
}

type PushResult struct {
	Applied     []uuid.UUID
	Conflicts   []Conflict
	NewRevision int64
}
