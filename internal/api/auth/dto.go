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

type LoginStartRequest struct {
	Email string `json:"email"`
}

type LoginStartResponse struct {
	AuthSalt  []byte `json:"auth_salt"`
	EncSalt   []byte `json:"enc_salt"`
	KDFParams []byte `json:"kdf_params"`
}

type LoginFinishRequest struct {
	Email          string `json:"email"`
	AuthKey        []byte `json:"auth_key"`
	DeviceID       string `json:"device_id"`
	DeviceName     string `json:"device_name"`
	DevicePlatform string `json:"device_platform"`
}

type LoginFinishResponse struct {
	AccessToken       string `json:"access_token"`
	RefreshToken      string `json:"refresh_token"`
	ExpiresIn         int    `json:"expires_in"`
	WrappedAccountKey []byte `json:"wrapped_account_key"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type RefreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}
