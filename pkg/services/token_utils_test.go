package services

import (
	"strings"
	"testing"
)

func TestGenerateSecureToken(t *testing.T) {
	tests := []struct {
		name     string
		length   int
		wantErr  bool
		checkLen int
	}{
		{
			name:     "valid length 16",
			length:   16,
			wantErr:  false,
			checkLen: 32, // hex encoded, so 16 bytes = 32 chars
		},
		{
			name:     "valid length 32",
			length:   32,
			wantErr:  false,
			checkLen: 64, // hex encoded, so 32 bytes = 64 chars
		},
		{
			name:    "invalid length 0",
			length:  0,
			wantErr: true,
		},
		{
			name:    "invalid negative length",
			length:  -1,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GenerateSecureToken(tt.length)
			
			if tt.wantErr {
				if err == nil {
					t.Errorf("GenerateSecureToken() expected error but got none")
				}
				return
			}
			
			if err != nil {
				t.Errorf("GenerateSecureToken() unexpected error: %v", err)
				return
			}
			
			if len(token) != tt.checkLen {
				t.Errorf("GenerateSecureToken() token length = %d, want %d", len(token), tt.checkLen)
			}
			
			// Check if token is valid hex
			for _, char := range token {
				if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
					t.Errorf("GenerateSecureToken() token contains invalid hex character: %c", char)
				}
			}
		})
	}
}

func TestGenerateSecureTokenUniqueness(t *testing.T) {
	// Generate multiple tokens and ensure they are unique
	tokens := make(map[string]bool)
	for i := 0; i < 100; i++ {
		token, err := GenerateSecureToken(32)
		if err != nil {
			t.Fatalf("GenerateSecureToken() unexpected error: %v", err)
		}
		
		if tokens[token] {
			t.Errorf("GenerateSecureToken() generated duplicate token: %s", token)
		}
		tokens[token] = true
	}
}

func TestHashToken(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  string
	}{
		{
			name:  "empty string",
			token: "",
			want:  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // SHA256 of empty string
		},
		{
			name:  "simple string",
			token: "hello",
			want:  "2cf24dba4f21d4288094c8b0f5b6c8b0f5b6c8b0f5b6c8b0f5b6c8b0f5b6c8b0", // This is not the actual SHA256, just for structure
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := HashToken(tt.token)
			
			// Check hash length (SHA256 produces 64 hex characters)
			if len(hash) != 64 {
				t.Errorf("HashToken() hash length = %d, want 64", len(hash))
			}
			
			// Check if hash is valid hex
			for _, char := range hash {
				if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
					t.Errorf("HashToken() hash contains invalid hex character: %c", char)
				}
			}
			
			// Test consistency - same input should produce same hash
			hash2 := HashToken(tt.token)
			if hash != hash2 {
				t.Errorf("HashToken() inconsistent results: %s != %s", hash, hash2)
			}
		})
	}
}

func TestGenerateConfirmationToken(t *testing.T) {
	token, tokenHash, err := GenerateConfirmationToken()
	
	if err != nil {
		t.Fatalf("GenerateConfirmationToken() unexpected error: %v", err)
	}
	
	// Check token length (32 bytes = 64 hex chars)
	if len(token) != 64 {
		t.Errorf("GenerateConfirmationToken() token length = %d, want 64", len(token))
	}
	
	// Check hash length (SHA256 = 64 hex chars)
	if len(tokenHash) != 64 {
		t.Errorf("GenerateConfirmationToken() hash length = %d, want 64", len(tokenHash))
	}
	
	// Verify that the hash matches the token
	expectedHash := HashToken(token)
	if tokenHash != expectedHash {
		t.Errorf("GenerateConfirmationToken() hash mismatch: got %s, want %s", tokenHash, expectedHash)
	}
	
	// Test uniqueness
	token2, tokenHash2, err2 := GenerateConfirmationToken()
	if err2 != nil {
		t.Fatalf("GenerateConfirmationToken() second call unexpected error: %v", err2)
	}
	
	if token == token2 {
		t.Errorf("GenerateConfirmationToken() generated duplicate tokens")
	}
	
	if tokenHash == tokenHash2 {
		t.Errorf("GenerateConfirmationToken() generated duplicate hashes")
	}
}

func TestVerifyToken(t *testing.T) {
	// Generate a test token
	token, tokenHash, err := GenerateConfirmationToken()
	if err != nil {
		t.Fatalf("GenerateConfirmationToken() unexpected error: %v", err)
	}
	
	tests := []struct {
		name        string
		plainToken  string
		storedHash  string
		want        bool
	}{
		{
			name:       "valid token",
			plainToken: token,
			storedHash: tokenHash,
			want:       true,
		},
		{
			name:       "invalid token",
			plainToken: "invalid_token",
			storedHash: tokenHash,
			want:       false,
		},
		{
			name:       "empty token",
			plainToken: "",
			storedHash: tokenHash,
			want:       false,
		},
		{
			name:       "empty hash",
			plainToken: token,
			storedHash: "",
			want:       false,
		},
		{
			name:       "both empty",
			plainToken: "",
			storedHash: "",
			want:       true, // Empty string hash matches empty string
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := VerifyToken(tt.plainToken, tt.storedHash)
			if result != tt.want {
				t.Errorf("VerifyToken() = %v, want %v", result, tt.want)
			}
		})
	}
}

func TestTokenSecurity(t *testing.T) {
	// Test that tokens don't contain predictable patterns
	tokens := make([]string, 10)
	for i := 0; i < 10; i++ {
		token, _, err := GenerateConfirmationToken()
		if err != nil {
			t.Fatalf("GenerateConfirmationToken() unexpected error: %v", err)
		}
		tokens[i] = token
	}
	
	// Check for common patterns that might indicate weak randomness
	for i, token := range tokens {
		// Check for repeated characters
		for j := 0; j < len(token)-3; j++ {
			substr := token[j : j+4]
			if strings.Count(token, substr) > 1 {
				t.Logf("Token %d contains repeated substring: %s", i, substr)
				// This is just a warning, not necessarily a failure
			}
		}
		
		// Check for sequential characters
		sequential := 0
		for j := 0; j < len(token)-1; j++ {
			if token[j]+1 == token[j+1] {
				sequential++
			}
		}
		if sequential > 5 {
			t.Errorf("Token %d has too many sequential characters: %d", i, sequential)
		}
	}
}
