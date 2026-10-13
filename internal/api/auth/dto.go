package auth

type RegisterRequest struct {
	Email             string `json:"email"`
	AuthKey           []byte `json:"auth_key"`
	AuthSalt          []byte `json:"auth_salt"`
	EncSalt           []byte `json:"enc_salt"`
	KDFParams         []byte `json:"kdf_params"`
	WrappedAccountKey []byte `json:"wrapped_account_key"`
}

type RegisterResponse struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	CreatedAt string `json:"created_at"`
}