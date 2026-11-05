package password

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/thecybersailor/slauth/pkg/config"
	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/flow/core"
	"github.com/thecybersailor/slauth/pkg/services"
	"github.com/thecybersailor/slauth/pkg/types"
)

// Deliberately provides no user store or rate limiter: rejected authentication
// must terminate before either is accessed.
type unverifiedService struct {
	services.AuthService
	claims map[string]any
	err    error
}

func (s unverifiedService) GetConfig() *config.AuthServiceConfig {
	cfg := &config.AuthServiceConfig{SecurityConfig: config.GetDefaultSecurityConfig()}
	cfg.SecurityConfig.PasswordUpdateConfig.UpdateRequiredAAL = types.AALLevel2
	return cfg
}
func (s unverifiedService) ValidateJWT(string) (map[string]any, error) { return s.claims, s.err }

func TestPasswordAuthenticationFailsBeforeQuotaAccess(t *testing.T) {
	for _, tc := range []struct {
		name, header   string
		claims         map[string]any
		jwtError, want error
	}{
		{name: "missing authorization", want: consts.NO_AUTHORIZATION},
		{name: "invalid token", header: "Bearer invalid", jwtError: errors.New("expired"), want: consts.BAD_JWT},
		{name: "missing assurance", header: "Bearer test", claims: map[string]any{}, want: consts.BAD_JWT},
		{name: "unverified session", header: "Bearer test", claims: map[string]any{"aal": types.AALLevel1}, want: consts.INSUFFICIENT_AAL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("PUT", "/password", nil)
			req.Header.Set("Authorization", tc.header)
			service := unverifiedService{claims: tc.claims, err: tc.jwtError}
			ctx := NewPasswordUpdateContext(context.Background(), service, req, &types.UpdatePasswordRequest{Password: "ChangedPassword123!"}, "user")
			for i := 0; i < 6; i++ {
				err := UpdatePasswordFlow(ctx)(&core.Context[core.PasswordChangeData]{Context: context.Background(), Data: core.PasswordChangeData{UserID: "user", NewPassword: "ChangedPassword123!"}}, func() error { t.Fatal("rejected authentication continued"); return nil })
				if !errors.Is(err, tc.want) {
					t.Fatalf("attempt %d: got %v, want %v", i+1, err, tc.want)
				}
			}
		})
	}
}
