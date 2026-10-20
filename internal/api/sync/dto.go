package sync

type ChangeInput struct {
	ID            string `json:"id"`
	EncryptedBlob []byte `json:"encrypted_blob"`
	BaseVersion   int64  `json:"base_version"`
	Deleted       bool   `json:"deleted"`
}

type PushRequest struct {
	Changes []ChangeInput `json:"changes"`
}

type ConflictResponse struct {
	ID            string `json:"id"`
	ServerVersion int64  `json:"server_version"`
}

type PushResponse struct {
	Applied     []string           `json:"applied"`
	Conflicts   []ConflictResponse `json:"conflicts"`
	NewRevision int64              `json:"new_revision"`
}

type ItemResponse struct {
	ID            string `json:"id"`
	EncryptedBlob []byte `json:"encrypted_blob"`
	Version       int64  `json:"version"`
	Deleted       bool   `json:"deleted"`
}

type PullResponse struct {
	Items       []ItemResponse `json:"items"`
	NewRevision int64          `json:"new_revision"`
}
