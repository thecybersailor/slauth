package services

import (
	"github.com/gin-gonic/gin"
	"github.com/thecybersailor/slauth/pkg/models"
)

type AuthContext struct {
	InstanceId  string         `json:"instance_id"`
	AuthService AuthService    `json:"-"`
	UserClaims  map[string]any `json:"user_claims,omitempty"`
	JWTToken    string         `json:"jwt_token,omitempty"`
	User        *models.User   `json:"user,omitempty"`
}

func getAuthContextKey(instanceId string) string {
	return "auth_context." + instanceId
}

func GetAuthContext(c *gin.Context, instanceId string) *AuthContext {
	ctx, exists := c.Get(getAuthContextKey(instanceId))
	if !exists {
		panic("AuthContext not found in gin.Context - middleware not properly configured")
	}
	authCtx, ok := ctx.(*AuthContext)
	if !ok {
		panic("Invalid AuthContext type in gin.Context")
	}
	return authCtx
}

func SetAuthContext(c *gin.Context, authCtx *AuthContext) {
	c.Set(getAuthContextKey(authCtx.InstanceId), authCtx)
}
