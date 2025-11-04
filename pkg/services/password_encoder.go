package services

// PasswordEncoder defines the interface for password hashing and verification
// This allows external projects to inject custom password encoding implementations
type PasswordEncoder interface {
	// HashPassword hashes a password and returns the encoded hash
	HashPassword(password string) (string, error)

	// VerifyPassword verifies a password against its encoded hash
	VerifyPassword(password, encodedHash string) (bool, error)
}

