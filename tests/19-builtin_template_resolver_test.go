package tests

import (
	"testing"

	"github.com/thecybersailor/slauth/pkg/services"
)

func TestBuiltinTemplateResolver(t *testing.T) {
	resolver := services.NewBuiltinTemplateResolver()

	tests := []struct {
		instanceId   string
		messageType  string
		templateName string
		shouldExist  bool
	}{
		{"test", "email", "verification-code", true},
		{"test", "email", "confirm-signup", true},
		{"test", "email", "change-email", true},
		{"test", "email", "invite-user", true},
		{"test", "email", "magic-link", true},
		{"test", "email", "reset-password", true},
		{"test", "sms", "verification-code", true},
		{"test", "sms", "reauthentication", true},

		{"test", "email", "non-existent", false},
		{"test", "sms", "non-existent", false},
		{"test", "unknown-type", "verification-code", false},
	}

	for _, tt := range tests {
		t.Run(tt.messageType+"/"+tt.templateName, func(t *testing.T) {
			templateBytes, found := resolver.GetTemplate(tt.instanceId, tt.messageType, tt.templateName)

			if found != tt.shouldExist {
				t.Errorf("GetTemplate(%s, %s, %s) = %v, want %v",
					tt.instanceId, tt.messageType, tt.templateName, found, tt.shouldExist)
			}

			if tt.shouldExist && len(templateBytes) == 0 {
				t.Errorf("GetTemplate(%s, %s, %s) returned empty template",
					tt.instanceId, tt.messageType, tt.templateName)
			}

			if !tt.shouldExist && templateBytes != nil {
				t.Errorf("GetTemplate(%s, %s, %s) returned non-nil template when should not exist",
					tt.instanceId, tt.messageType, tt.templateName)
			}
		})
	}
}

func TestBuiltinTemplateResolverContent(t *testing.T) {
	resolver := services.NewBuiltinTemplateResolver()

	templateBytes, found := resolver.GetTemplate("test", "email", "verification-code")
	if !found {
		t.Fatal("verification-code template should exist")
	}

	content := string(templateBytes)

	expectedContent := []string{
		"# Subject: Your verification code",
		"<h2>Your verification code</h2>",
		"{{ .Code }}",
	}

	for _, expected := range expectedContent {
		if !contains(content, expected) {
			t.Errorf("Template content should contain '%s', but got: %s", expected, content)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > len(substr) && (s[:len(substr)] == substr ||
			s[len(s)-len(substr):] == substr ||
			containsSubstring(s, substr))))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
