package core

type SignupData struct {
	Email    string                 `json:"email"`
	Phone    string                 `json:"phone"`
	Password string                 `json:"password"`
	UserData map[string]interface{} `json:"user_data"`
	UserID   string                 `json:"user_id,omitempty"`
	Action   string                 `json:"action"`
}

type SigninData struct {
	EmailOrPhone string `json:"email_or_phone"`
	Password     string `json:"password,omitempty"`
	UserID       string `json:"user_id,omitempty"`
	SessionID    string `json:"session_id,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	Action       string `json:"action"`
}

type PasswordResetData struct {
	Email    string `json:"email"`
	Phone    string `json:"phone,omitempty"`
	ResetURL string `json:"reset_url,omitempty"`
	Token    string `json:"token,omitempty"`
	Action   string `json:"action"`
}

type PasswordChangeData struct {
	UserID          string `json:"user_id"`
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
	Action          string `json:"action"`
}
