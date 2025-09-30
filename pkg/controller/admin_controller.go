package controller

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/flaboy/pin"
	"github.com/speps/go-hashids/v2"
	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/services"
	"gorm.io/gorm"
)

// AdminController handles admin operations
type AdminController struct {
	authService services.AuthService
}

// NewAdminController creates a new AdminController instance
func NewAdminController(authService services.AuthService) *AdminController {
	return &AdminController{
		authService: authService,
	}
}

// ===== User Management =====

// QueryUsers handles POST /admin/users/query
// @Summary Query Users (Strapi-style)
// @Description Query users with complex filters using Strapi-style syntax
// @Tags Admin
// @Accept json
// @Produce json
// @Security AdminAuth
// @Param request body QueryUsersRequest true "Query request with filters, sort, and pagination"
// @Success 200 {object} ListUsersResponse "Users retrieved successfully"
// @Router /admin/users/query [post]
func (c *AdminController) QueryUsers(ctx *pin.Context) error {
	var req QueryUsersRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		return consts.VALIDATION_FAILED
	}

	// Set pagination defaults
	page := 1
	pageSize := 20
	if req.Pagination != nil {
		if req.Pagination.Page > 0 {
			page = req.Pagination.Page
		}
		if req.Pagination.PageSize > 0 {
			pageSize = req.Pagination.PageSize
		}
		if pageSize > 100 {
			pageSize = 100
		}
	}

	// Build query from filters using QueryBuilder
	qb := NewQueryBuilder(c.authService.GetDB(), c.authService.GetDomainCode())
	qb.applyFilters(req.Filters)
	query := qb.Build()

	// Apply sorting
	if len(req.Sort) > 0 {
		query = applySorting(query, req.Sort)
	} else {
		query = query.Order("users.created_at DESC")
	}

	// Count total
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return err
	}

	// Apply pagination
	offset := (page - 1) * pageSize
	query = query.Offset(offset).Limit(pageSize)

	// Execute query
	var users []models.User
	if err := query.Find(&users).Error; err != nil {
		return err
	}

	// Convert to response
	adminUsers := make([]*AdminUserResponse, 0, len(users))
	for i := range users {
		adminUser := convertModelUserToAdminResponse(&users[i])
		if adminUser != nil {
			adminUsers = append(adminUsers, adminUser)
		}
	}

	response := ListUsersResponse{
		Users:    adminUsers,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}

	return ctx.Render(response)
}

// GetUser handles GET /admin/users/:id
// @Summary Get User by ID
// @Description Get detailed user information by user ID
// @Tags Admin
// @Produce json
// @Security AdminAuth
// @Param id path string true "User ID"
// @Success 200 {object} AdminUserResponse "User retrieved successfully"
// @Router /admin/users/{id} [get]
func (c *AdminController) GetUser(ctx *pin.Context) error {
	userID := ctx.Param("id")
	if userID == "" {
		return consts.VALIDATION_FAILED
	}

	user, err := c.authService.GetUserService().GetByHashID(ctx.Request.Context(), userID)
	if err != nil {
		return consts.USER_NOT_FOUND
	}

	response := convertUserToAdminResponse(user)
	return ctx.Render(response)
}

// @Summary Update User
// @Description Update user information (admin only)
// @Tags Admin
// @Accept json
// @Produce json
// @Security AdminAuth
// @Param id path string true "User ID"
// @Param request body AdminUpdateUserRequest true "User update data"
// @Success 200 {object} AdminUserResponse "User updated successfully"
// @Router /admin/users/{id} [put]
// UpdateUser handles PUT /admin/users/:id
func (c *AdminController) UpdateUser(ctx *pin.Context) error {
	userID := ctx.Param("id")
	if userID == "" {
		return consts.VALIDATION_FAILED
	}

	var req AdminUpdateUserRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		return consts.VALIDATION_FAILED
	}

	updates := make(map[string]any)
	if req.Email != nil {
		updates["email"] = *req.Email
	}
	if req.Phone != nil {
		updates["phone"] = *req.Phone
	}
	if req.UserData != nil {
		updates["user_data"] = req.UserData
	}
	if req.EmailConfirmed != nil {
		updates["email_confirmed"] = *req.EmailConfirmed
	}
	if req.PhoneConfirmed != nil {
		updates["phone_confirmed"] = *req.PhoneConfirmed
	}
	if req.BannedUntil != nil {
		updates["banned_until"] = *req.BannedUntil
	}

	// Get user first, then update individual fields
	user, err := c.authService.GetUserService().GetByHashID(ctx.Request.Context(), userID)
	if err != nil {
		return err
	}

	// Update fields individually using User methods
	if email, ok := updates["email"].(string); ok {
		err = user.UpdateEmail(ctx.Request.Context(), email)
		if err != nil {
			return err
		}
	}
	if phone, ok := updates["phone"].(string); ok {
		err = user.UpdatePhone(ctx.Request.Context(), phone)
		if err != nil {
			return err
		}
	}
	if bannedUntil, ok := updates["banned_until"].(time.Time); ok {
		err = user.SetBan(ctx.Request.Context(), bannedUntil)
		if err != nil {
			return err
		}
	}

	// Update AppMetadata if provided
	if req.AppMetadata != nil {
		err = user.UpdateAppMetadata(ctx.Request.Context(), req.AppMetadata)
		if err != nil {
			return err
		}
	}

	if err != nil {
		return err
	}

	response := convertUserToAdminResponse(user)
	return ctx.Render(response)
}

// @Summary Delete User
// @Description Delete user account (admin only)
// @Tags Admin
// @Produce json
// @Security AdminAuth
// @Param id path string true "User ID"
// @Success 200 {object} map[string]string "User deleted successfully"
// @Router /admin/users/{id} [delete]
// DeleteUser handles DELETE /admin/users/:id
func (c *AdminController) DeleteUser(ctx *pin.Context) error {
	userID := ctx.Param("id")
	if userID == "" {
		return consts.VALIDATION_FAILED
	}

	// Get user and delete
	user, err := c.authService.GetUserService().GetByHashID(ctx.Request.Context(), userID)
	if err != nil {
		return err
	}
	err = user.Delete(ctx.Request.Context())
	if err != nil {
		return err
	}

	return ctx.Render(map[string]string{"message": "user deleted successfully"})
}

// CreateUser handles POST /admin/users
// @Summary Create New User
// @Description Create a new user account (admin only)
// @Tags Admin
// @Accept json
// @Produce json
// @Security AdminAuth
// @Param request body AdminCreateUserRequest true "User creation request"
// @Success 200 {object} AdminUserResponse "User created successfully"
// @Router /admin/users [post]
func (c *AdminController) CreateUser(ctx *pin.Context) error {
	var req AdminCreateUserRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		return consts.VALIDATION_FAILED
	}

	userMetaData := make(map[string]interface{})
	appMetaData := make(map[string]interface{})

	if req.UserData != nil {
		for k, v := range req.UserData {
			userMetaData[k] = v
		}
	}

	if req.UserMetadata != nil {
		for k, v := range req.UserMetadata {
			userMetaData[k] = v
		}
	}

	if req.AppMetadata != nil {
		for k, v := range req.AppMetadata {
			appMetaData[k] = v
		}
	}

	user, err := services.CreateUserWithMetadata(
		ctx.Request.Context(),
		c.authService.GetDB(),
		c.authService.GetDomainCode(),
		req.Email,
		req.Phone,
		req.Password,
		userMetaData,
		appMetaData,
	)
	if err != nil {
		return err
	}

	// Confirm email if requested
	if req.EmailConfirmed {
		err = user.ConfirmEmail(ctx.Request.Context())
		if err != nil {
			return err
		}
	}

	// Confirm phone if requested
	if req.PhoneConfirmed {
		err = user.ConfirmPhone(ctx.Request.Context())
		if err != nil {
			return err
		}
	}

	response := convertUserToAdminResponse(user)
	return ctx.Render(response)
}

// @Summary Reset User Password
// @Description Reset user password (admin only)
// @Tags Admin
// @Accept json
// @Produce json
// @Security AdminAuth
// @Param id path string true "User ID"
// @Param request body AdminResetPasswordRequest true "Password reset data"
// @Success 200 {object} map[string]string "Password reset successfully"
// @Router /admin/users/{id}/reset-password [post]
// ResetUserPassword handles POST /admin/users/:id/reset-password
func (c *AdminController) ResetUserPassword(ctx *pin.Context) error {
	userID := ctx.Param("id")
	if userID == "" {
		return consts.VALIDATION_FAILED
	}

	var req AdminResetPasswordRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		return consts.VALIDATION_FAILED
	}

	// Get user and update password
	user, err := c.authService.GetUserService().GetByHashID(ctx.Request.Context(), userID)
	if err != nil {
		return err
	}
	err = user.UpdatePassword(ctx.Request.Context(), req.NewPassword)
	if err != nil {
		return err
	}

	return ctx.Render(map[string]string{"message": "password reset successfully"})
}

// SetUserEmailConfirmed handles PUT /admin/users/:id/email-confirmed
// @Summary Set User Email Confirmed Status
// @Description Set user email confirmation status (admin only)
// @Tags Admin
// @Accept json
// @Produce json
// @Security AdminAuth
// @Param id path string true "User ID"
// @Param request body object{confirmed=bool} true "Email confirmation status"
// @Success 200 {object} map[string]string "Email confirmation status updated successfully"
// @Router /admin/users/{id}/email-confirmed [put]
func (c *AdminController) SetUserEmailConfirmed(ctx *pin.Context) error {
	userID := ctx.Param("id")
	if userID == "" {
		return consts.VALIDATION_FAILED
	}

	var req struct {
		Confirmed bool `json:"confirmed"`
	}
	if err := ctx.ShouldBindJSON(&req); err != nil {
		return consts.VALIDATION_FAILED
	}

	// Get user and confirm/unconfirm email
	user, err := c.authService.GetUserService().GetByHashID(ctx.Request.Context(), userID)
	if err != nil {
		return err
	}
	if req.Confirmed {
		err = user.ConfirmEmail(ctx.Request.Context())
	} else {
		// For unconfirming, we need to directly update the database
		err = user.GetDB().WithContext(ctx.Request.Context()).Model(&models.User{}).
			Where("id = ? AND domain_code = ?", user.ID, user.GetDomainCode()).
			Updates(map[string]any{
				"email_confirmed_at": nil,
				"updated_at":         time.Now(),
			}).Error
		if err == nil {
			user.EmailConfirmedAt = nil
			user.UpdatedAt = time.Now()
		}
	}
	if err != nil {
		return err
	}

	return ctx.Render(map[string]string{"message": "email confirmation status updated"})
}

// SetUserPhoneConfirmed handles PUT /admin/users/:id/phone-confirmed
// @Summary Set User Phone Confirmed Status
// @Description Set user phone confirmation status (admin only)
// @Tags Admin
// @Accept json
// @Produce json
// @Security AdminAuth
// @Param id path string true "User ID"
// @Param request body object{confirmed=bool} true "Phone confirmation status"
// @Success 200 {object} map[string]string "Phone confirmation status updated successfully"
// @Router /admin/users/{id}/phone-confirmed [put]
func (c *AdminController) SetUserPhoneConfirmed(ctx *pin.Context) error {
	userID := ctx.Param("id")
	if userID == "" {
		return consts.VALIDATION_FAILED
	}

	var req struct {
		Confirmed bool `json:"confirmed"`
	}
	if err := ctx.ShouldBindJSON(&req); err != nil {
		return consts.VALIDATION_FAILED
	}

	// Get user and confirm/unconfirm phone
	user, err := c.authService.GetUserService().GetByHashID(ctx.Request.Context(), userID)
	if err != nil {
		return err
	}
	if req.Confirmed {
		err = user.ConfirmPhone(ctx.Request.Context())
	} else {
		// For unconfirming, we need to directly update the database
		err = user.GetDB().WithContext(ctx.Request.Context()).Model(&models.User{}).
			Where("id = ? AND domain_code = ?", user.ID, user.GetDomainCode()).
			Updates(map[string]any{
				"phone_confirmed_at": nil,
				"updated_at":         time.Now(),
			}).Error
		if err == nil {
			user.PhoneConfirmedAt = nil
			user.UpdatedAt = time.Now()
		}
	}
	if err != nil {
		return err
	}

	return ctx.Render(map[string]string{"message": "phone confirmation status updated"})
}

// ===== Session Management =====

// ListUserSessions handles GET /admin/users/:id/sessions
// @Summary List User Sessions
// @Description Get list of user sessions (admin only)
// @Tags Admin
// @Produce json
// @Security AdminAuth
// @Param id path string true "User ID"
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Success 200 {object} ListSessionsResponse "User sessions retrieved successfully"
// @Router /admin/users/{id}/sessions [get]
func (c *AdminController) ListUserSessions(ctx *pin.Context) error {
	userID := ctx.Param("id")
	if userID == "" {
		return consts.VALIDATION_FAILED
	}

	var req ListSessionsRequest
	if err := ctx.ShouldBindQuery(&req); err != nil {
		return consts.VALIDATION_FAILED
	}

	// Set defaults and validate
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.PageSize <= 0 {
		req.PageSize = 20
	}
	if req.PageSize > 100 {
		req.PageSize = 100
	}

	// Get user first, then list sessions
	user, err := c.authService.GetUserService().GetByHashID(ctx.Request.Context(), userID)
	if err != nil {
		return err
	}
	sessions, total, err := user.ListSessions(ctx.Request.Context(), req.Page, req.PageSize)
	if err != nil {
		return err
	}

	response := ListSessionsResponse{
		Sessions: convertSessionsToResponse(sessions),
		Total:    total,
		Page:     req.Page,
		PageSize: req.PageSize,
	}

	return ctx.Render(response)
}

// RevokeUserSession handles DELETE /admin/sessions/:id
// @Summary Revoke User Session
// @Description Revoke a specific user session (admin only)
// @Tags Admin
// @Produce json
// @Security AdminAuth
// @Param id path string true "Session ID"
// @Success 200 {object} map[string]string "Session revoked successfully"
// @Router /admin/sessions/{id} [delete]
func (c *AdminController) RevokeUserSession(ctx *pin.Context) error {
	sessionID := ctx.Param("id")
	if sessionID == "" {
		return consts.VALIDATION_FAILED
	}

	err := c.authService.GetAdminSessionService().RevokeUserSession(ctx.Request.Context(), c.authService.GetDomainCode(), sessionID)
	if err != nil {
		return err
	}

	return ctx.Render(map[string]string{"message": "session revoked successfully"})
}

// RevokeAllUserSessions handles DELETE /admin/users/:id/sessions
// @Summary Revoke All User Sessions
// @Description Revoke all sessions for a specific user (admin only)
// @Tags Admin
// @Produce json
// @Security AdminAuth
// @Param id path string true "User ID"
// @Success 200 {object} map[string]string "All user sessions revoked successfully"
// @Router /admin/users/{id}/sessions [delete]
func (c *AdminController) RevokeAllUserSessions(ctx *pin.Context) error {
	userID := ctx.Param("id")
	if userID == "" {
		return consts.VALIDATION_FAILED
	}

	// Get user first, then revoke all sessions
	user, err := c.authService.GetUserService().GetByHashID(ctx.Request.Context(), userID)
	if err != nil {
		return err
	}
	err = user.RevokeAllSessions(ctx.Request.Context())
	if err != nil {
		return err
	}

	return ctx.Render(map[string]string{"message": "all user sessions revoked successfully"})
}

// ListAllSessions handles GET /admin/sessions
// @Summary List All Sessions
// @Description List all user sessions (admin only)
// @Tags Admin
// @Produce json
// @Security AdminAuth
// @Success 200 {object} ListSessionsResponse "Sessions retrieved successfully"
// @Router /admin/sessions [get]
func (c *AdminController) ListAllSessions(ctx *pin.Context) error {
	var req ListSessionsRequest
	if err := ctx.ShouldBindQuery(&req); err != nil {
		return consts.VALIDATION_FAILED
	}

	// Set defaults and validate
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.PageSize <= 0 {
		req.PageSize = 20
	}
	if req.PageSize > 100 {
		req.PageSize = 100
	}

	sessions, total, err := c.authService.GetAdminSessionService().ListAllSessions(ctx.Request.Context(), c.authService.GetDomainCode(), req.Page, req.PageSize, nil)
	if err != nil {
		return err
	}

	response := ListSessionsResponse{
		Sessions: convertSessionsToResponse(sessions),
		Total:    total,
		Page:     req.Page,
		PageSize: req.PageSize,
	}

	return ctx.Render(response)
}

// ===== Identity Management =====

// ListUserIdentities handles GET /admin/users/:id/identities
// @Summary List User Identities
// @Description List user identities (admin only)
// @Tags Admin
// @Produce json
// @Security AdminAuth
// @Param id path string true "User ID"
// @Success 200 {object} map[string]interface{} "User identities retrieved successfully"
// @Router /admin/users/{id}/identities [get]
func (c *AdminController) ListUserIdentities(ctx *pin.Context) error {
	userID := ctx.Param("id")
	if userID == "" {
		return consts.VALIDATION_FAILED
	}

	// Get user first, then list identities
	user, err := c.authService.GetUserService().GetByHashID(ctx.Request.Context(), userID)
	if err != nil {
		return err
	}
	identities, err := user.ListIdentities(ctx.Request.Context())
	if err != nil {
		return err
	}

	response := ListIdentitiesResponse{
		Identities: convertIdentitiesToResponse(identities),
	}

	return ctx.Render(response)
}

// DeleteUserIdentity handles DELETE /admin/users/:id/identities/:identity_id
// @Summary Delete User Identity
// @Description Delete user identity (admin only)
// @Tags Admin
// @Produce json
// @Security AdminAuth
// @Param id path string true "User ID"
// @Param identity_id path string true "Identity ID"
// @Success 200 {object} map[string]string "Identity deleted successfully"
// @Router /admin/users/{id}/identities/{identity_id} [delete]
func (c *AdminController) DeleteUserIdentity(ctx *pin.Context) error {
	userID := ctx.Param("id")
	identityID := ctx.Param("identity_id")
	if userID == "" || identityID == "" {
		return consts.VALIDATION_FAILED
	}

	// Get user first, then delete identity
	user, err := c.authService.GetUserService().GetByHashID(ctx.Request.Context(), userID)
	if err != nil {
		return err
	}
	err = user.DeleteIdentity(ctx.Request.Context(), identityID)
	if err != nil {
		return err
	}

	return ctx.Render(map[string]string{"message": "identity deleted successfully"})
}

// ===== System Management =====

// GetUserCount handles GET /admin/stats/users
// @Summary Get User Count
// @Description Get total user count (admin only)
// @Tags Admin
// @Produce json
// @Security AdminAuth
// @Success 200 {object} StatsResponse "User count retrieved successfully"
// @Router /admin/stats/users [get]
func (c *AdminController) GetUserCount(ctx *pin.Context) error {
	count, err := c.authService.GetAdminSystemService().GetUserCount(ctx.Request.Context(), c.authService.GetDomainCode())
	if err != nil {
		return err
	}

	response := StatsResponse{Count: count}
	return ctx.Render(response)
}

// GetActiveSessionCount handles GET /admin/stats/sessions
// @Summary Get Active Session Count
// @Description Get active session count (admin only)
// @Tags Admin
// @Produce json
// @Security AdminAuth
// @Success 200 {object} SessionStatsResponse "Session count retrieved successfully"
// @Router /admin/stats/sessions [get]
func (c *AdminController) GetActiveSessionCount(ctx *pin.Context) error {
	activeCount, err := c.authService.GetAdminSystemService().GetActiveSessionCount(ctx.Request.Context(), c.authService.GetDomainCode())
	if err != nil {
		return consts.UNEXPECTED_FAILURE
	}

	// For now, return simplified stats - we'll need to implement GetSessionStats later
	return ctx.Render(&SessionStatsResponse{
		TotalSessions:   activeCount, // Assume all sessions are active for now
		ActiveSessions:  activeCount,
		ExpiredSessions: 0,
	})
}

// GetRecentSignups handles GET /admin/stats/recent-signups
// @Summary Get Recent Signups
// @Description Get recent user signups statistics (admin only)
// @Tags Admin
// @Produce json
// @Security AdminAuth
// @Success 200 {object} map[string]interface{} "Recent signups retrieved successfully"
// @Router /admin/stats/recent-signups [get]
func (c *AdminController) GetRecentSignups(ctx *pin.Context) error {
	var req RecentSignupsRequest
	if err := ctx.ShouldBindQuery(&req); err != nil {
		return consts.VALIDATION_FAILED
	}

	// Set default and validate
	if req.Days <= 0 {
		req.Days = 7
	}
	if req.Days > 365 {
		req.Days = 365
	}

	users, err := c.authService.GetAdminSystemService().GetRecentSignups(ctx.Request.Context(), c.authService.GetDomainCode(), req.Days)
	if err != nil {
		return err
	}

	response := ListUsersResponse{
		Users:    convertUsersToResponse(users),
		Total:    int64(len(users)),
		Page:     1,
		PageSize: len(users),
	}

	return ctx.Render(response)
}

// GetRecentSignins handles GET /admin/stats/recent-signins
// @Summary Get Recent Signins
// @Description Get recent user signins statistics (admin only)
// @Tags Admin
// @Produce json
// @Security AdminAuth
// @Success 200 {object} map[string]interface{} "Recent signins retrieved successfully"
// @Router /admin/stats/recent-signins [get]
func (c *AdminController) GetRecentSignins(ctx *pin.Context) error {
	var req ListRecentSigninsRequest
	if err := ctx.ShouldBindQuery(&req); err != nil {
		return consts.VALIDATION_FAILED
	}

	// Set default and validate
	if req.Limit <= 0 {
		req.Limit = 50
	}
	if req.Limit > 100 {
		req.Limit = 100
	}

	signins, err := c.authService.GetAdminSystemService().GetRecentSignins(ctx.Request.Context(), c.authService.GetDomainCode(), 7)
	if err != nil {
		return consts.UNEXPECTED_FAILURE
	}

	// Convert to response format
	var signinResponses []*RecentSigninResponse
	for _, signin := range signins {
		// Handle nil user
		if signin.User == nil {
			continue // Skip sessions without user data
		}

		// Generate user hashid
		userHashID := generateUserHashID(signin.User.ID)

		// Handle pointer fields
		email := ""
		if signin.User.Email != nil {
			email = *signin.User.Email
		}
		ip := ""
		if signin.IP != nil {
			ip = *signin.IP
		}
		userAgent := ""
		if signin.UserAgent != nil {
			userAgent = *signin.UserAgent
		}

		signinResponses = append(signinResponses, &RecentSigninResponse{
			UserID:    userHashID,
			Email:     email,
			SigninAt:  signin.CreatedAt.Format(time.RFC3339),
			IPAddress: ip,
			UserAgent: userAgent,
		})
	}

	return ctx.Render(&RecentSigninsResponse{
		RecentSignins: signinResponses,
	})
}

// ===== Helper Functions =====

// generateUserHashID generates a hashid for a user ID
func generateUserHashID(userID uint) string {
	hd := hashids.NewData()
	hd.Salt = "@cybersailor/slauth-ts-salt" // Use same salt as objects package
	hd.MinLength = 8

	h, err := hashids.NewWithData(hd)
	if err != nil {
		return strconv.Itoa(int(userID)) // Fallback to plain ID
	}

	hashid, err := h.Encode([]int{int(userID)})
	if err != nil {
		return strconv.Itoa(int(userID)) // Fallback to plain ID
	}

	return hashid
}

func convertUsersToResponse(users []*services.User) []*AdminUserResponse {
	result := make([]*AdminUserResponse, len(users))
	for i, user := range users {
		result[i] = convertUserToAdminResponse(user)
	}
	return result
}

func convertUserToAdminResponse(user *services.User) *AdminUserResponse {
	response := &AdminUserResponse{
		ID:             user.HashID,
		EmailConfirmed: user.EmailConfirmedAt != nil,
		PhoneConfirmed: user.PhoneConfirmedAt != nil,
		IsAnonymous:    user.IsAnonymous(),
		CreatedAt:      user.CreatedAt.Format(time.RFC3339),
		UpdatedAt:      user.UpdatedAt.Format(time.RFC3339),
	}

	if user.Email != nil {
		response.Email = user.Email
	}
	if user.Phone != nil {
		response.Phone = user.Phone
	}
	if user.BannedUntil != nil {
		bannedUntil := user.BannedUntil.Format(time.RFC3339)
		response.BannedUntil = &bannedUntil
	}
	if user.LastSignInAt != nil {
		lastSignInAt := user.LastSignInAt.Format(time.RFC3339)
		response.LastSignInAt = &lastSignInAt
	}
	if user.RawUserMetaData != nil {
		// Convert JSON.RawMessage to map[string]interface{}
		var userMeta map[string]interface{}
		if err := json.Unmarshal(*user.RawUserMetaData, &userMeta); err == nil {
			response.RawUserMetaData = userMeta
		}
	}
	if user.RawAppMetaData != nil {
		// Convert JSON.RawMessage to map[string]interface{}
		var appMeta map[string]interface{}
		if err := json.Unmarshal(*user.RawAppMetaData, &appMeta); err == nil {
			response.RawAppMetaData = appMeta
		}
	}

	return response
}

func convertSessionsToResponse(sessions []*services.Session) []*SessionResponse {
	result := make([]*SessionResponse, len(sessions))
	for i, session := range sessions {
		result[i] = convertSessionToResponse(session)
	}
	return result
}

func convertSessionToResponse(session *services.Session) *SessionResponse {
	// Generate user hashid
	userHashID, err := services.GenerateUserHashID(session.UserID)
	if err != nil {
		// Fallback to raw ID if hashid generation fails
		userHashID = strconv.FormatUint(uint64(session.UserID), 10)
	}

	response := &SessionResponse{
		ID:        session.HashID,
		UserID:    userHashID,
		CreatedAt: session.CreatedAt.Format(time.RFC3339),
		UpdatedAt: session.UpdatedAt.Format(time.RFC3339),
	}

	if session.AAL != nil {
		response.AAL = string(*session.AAL)
	}
	if session.UserAgent != nil {
		response.UserAgent = session.UserAgent
	}
	if session.IP != nil {
		response.IP = session.IP
	}
	if session.RefreshedAt != nil {
		refreshedAt := session.RefreshedAt.Format(time.RFC3339)
		response.RefreshedAt = &refreshedAt
	}

	return response
}

func convertIdentitiesToResponse(identities []*services.UserIdentity) []*IdentityResponse {
	result := make([]*IdentityResponse, len(identities))
	for i, identity := range identities {
		result[i] = convertIdentityToAdminResponse(identity)
	}
	return result
}

func convertIdentityToAdminResponse(identity *services.UserIdentity) *IdentityResponse {
	response := &IdentityResponse{
		ID:         identity.HashID,
		Provider:   identity.Provider,
		ProviderID: identity.ProviderID,
		CreatedAt:  identity.CreatedAt.Format(time.RFC3339),
		UpdatedAt:  identity.UpdatedAt.Format(time.RFC3339),
	}

	// Convert JSON.RawMessage to map[string]interface{}
	var identityData map[string]interface{}
	if err := json.Unmarshal(identity.IdentityData, &identityData); err == nil {
		response.IdentityData = identityData
	}

	return response
}

// ===== SAML SSO Management =====

// CreateSAMLProvider handles POST /admin/saml/providers
// @Summary Create SAML Provider
// @Description Create a new SAML SSO provider (admin only)
// @Tags Admin
// @Accept json
// @Produce json
// @Security AdminAuth
// @Param request body CreateSAMLProviderRequest true "SAML provider creation request"
// @Success 200 {object} SAMLProviderResponse "SAML provider created successfully"
// @Router /admin/saml/providers [post]
func (c *AdminController) CreateSAMLProvider(ctx *pin.Context) error {
	var req CreateSAMLProviderRequest
	if err := ctx.BindJSON(&req); err != nil {
		return consts.BAD_JSON
	}

	// Validate required fields
	if req.Name == "" {
		return consts.VALIDATION_FAILED
	}

	// Create SAML service
	samlService := services.NewSAMLService(c.authService.GetDB(), c.authService.GetDomainCode())

	// Create SSO provider
	ssoProvider, err := samlService.CreateSSOProvider(ctx.Request.Context(), req.Name, req.Enabled)
	if err != nil {
		return consts.UNEXPECTED_FAILURE
	}

	return ctx.Render(&SAMLProviderResponse{
		ID:        ssoProvider.HashID,
		Name:      ssoProvider.Name,
		Enabled:   ssoProvider.Enabled,
		CreatedAt: ssoProvider.CreatedAt.Format(time.RFC3339),
		UpdatedAt: ssoProvider.UpdatedAt.Format(time.RFC3339),
	})
}

// ListSAMLProviders handles GET /admin/saml/providers
// @Summary List SAML Providers
// @Description Get list of SAML SSO providers (admin only)
// @Tags Admin
// @Produce json
// @Security AdminAuth
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Success 200 {object} ListSAMLProvidersResponse "SAML providers retrieved successfully"
// @Router /admin/saml/providers [get]
func (c *AdminController) ListSAMLProviders(ctx *pin.Context) error {
	var req ListSAMLProvidersRequest
	if err := ctx.ShouldBindQuery(&req); err != nil {
		return consts.VALIDATION_FAILED
	}

	// Set defaults
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.PageSize <= 0 {
		req.PageSize = 20
	}
	if req.PageSize > 100 {
		req.PageSize = 100
	}

	// Create SAML service
	samlService := services.NewSAMLService(c.authService.GetDB(), c.authService.GetDomainCode())

	// Get providers
	providers, total, err := samlService.ListSSOProviders(ctx.Request.Context(), req.Page, req.PageSize)
	if err != nil {
		return consts.UNEXPECTED_FAILURE
	}

	// Convert to response format
	result := make([]*SAMLProviderResponse, len(providers))
	for i, provider := range providers {
		result[i] = &SAMLProviderResponse{
			ID:        provider.HashID,
			Name:      provider.Name,
			Enabled:   provider.Enabled,
			CreatedAt: provider.CreatedAt.Format(time.RFC3339),
			UpdatedAt: provider.UpdatedAt.Format(time.RFC3339),
		}
	}

	return ctx.Render(&ListSAMLProvidersResponse{
		Providers: result,
		Total:     total,
		Page:      req.Page,
		PageSize:  req.PageSize,
	})
}

// GetSAMLProvider handles GET /admin/saml/providers/:id
// @Summary Get SAML Provider
// @Description Get SAML provider details (admin only)
// @Tags Admin
// @Produce json
// @Security AdminAuth
// @Param id path string true "Provider ID"
// @Success 200 {object} SAMLProviderResponse "SAML provider retrieved successfully"
// @Router /admin/saml/providers/{id} [get]
func (c *AdminController) GetSAMLProvider(ctx *pin.Context) error {
	providerID := ctx.Param("id")
	if providerID == "" {
		return consts.VALIDATION_FAILED
	}

	// Create SAML service
	samlService := services.NewSAMLService(c.authService.GetDB(), c.authService.GetDomainCode())

	// Find provider
	provider, err := samlService.FindSSOProviderByID(ctx.Request.Context(), providerID)
	if err != nil {
		return consts.SSO_PROVIDER_NOT_FOUND
	}

	// Get SAML configuration if exists
	samlConfig, err := samlService.GetSAMLProvider(ctx.Request.Context(), provider)
	var samlResp *SAMLConfigResponse
	if err == nil {
		samlResp = &SAMLConfigResponse{
			EntityID:         samlConfig.EntityID,
			MetadataURL:      samlConfig.MetadataURL,
			NameIDFormat:     samlConfig.NameIDFormat,
			AttributeMapping: samlConfig.AttributeMapping,
		}
	}

	return ctx.Render(&SAMLProviderDetailResponse{
		ID:         provider.HashID,
		Name:       provider.Name,
		Enabled:    provider.Enabled,
		CreatedAt:  provider.CreatedAt.Format(time.RFC3339),
		UpdatedAt:  provider.UpdatedAt.Format(time.RFC3339),
		SAMLConfig: samlResp,
	})
}

// UpdateSAMLProvider handles PUT /admin/saml/providers/:id
// @Summary Update SAML Provider
// @Description Update SAML provider configuration (admin only)
// @Tags Admin
// @Accept json
// @Produce json
// @Security AdminAuth
// @Param id path string true "Provider ID"
// @Param request body UpdateSAMLProviderRequest true "SAML provider update request"
// @Success 200 {object} SAMLProviderResponse "SAML provider updated successfully"
// @Router /admin/saml/providers/{id} [put]
func (c *AdminController) UpdateSAMLProvider(ctx *pin.Context) error {
	providerID := ctx.Param("id")
	if providerID == "" {
		return consts.VALIDATION_FAILED
	}

	var req UpdateSAMLProviderRequest
	if err := ctx.BindJSON(&req); err != nil {
		return consts.BAD_JSON
	}

	// Create SAML service
	samlService := services.NewSAMLService(c.authService.GetDB(), c.authService.GetDomainCode())

	// Build updates map
	updates := make(map[string]interface{})
	if req.Name != nil {
		updates["name"] = *req.Name
	}
	if req.Enabled != nil {
		updates["enabled"] = *req.Enabled
	}

	// Update provider
	provider, err := samlService.UpdateSSOProvider(ctx.Request.Context(), providerID, updates)
	if err != nil {
		return consts.SSO_PROVIDER_NOT_FOUND
	}

	return ctx.Render(&SAMLProviderResponse{
		ID:        provider.HashID,
		Name:      provider.Name,
		Enabled:   provider.Enabled,
		CreatedAt: provider.CreatedAt.Format(time.RFC3339),
		UpdatedAt: provider.UpdatedAt.Format(time.RFC3339),
	})
}

// DeleteSAMLProvider handles DELETE /admin/saml/providers/:id
// @Summary Delete SAML Provider
// @Description Delete SAML provider (admin only)
// @Tags Admin
// @Produce json
// @Security AdminAuth
// @Param id path string true "Provider ID"
// @Success 200 {object} map[string]string "SAML provider deleted successfully"
// @Router /admin/saml/providers/{id} [delete]
func (c *AdminController) DeleteSAMLProvider(ctx *pin.Context) error {
	providerID := ctx.Param("id")
	if providerID == "" {
		return consts.VALIDATION_FAILED
	}

	// Create SAML service
	samlService := services.NewSAMLService(c.authService.GetDB(), c.authService.GetDomainCode())

	// Delete provider
	if err := samlService.DeleteSSOProvider(ctx.Request.Context(), providerID); err != nil {
		return consts.SSO_PROVIDER_NOT_FOUND
	}

	return ctx.Render(map[string]string{"message": "SAML provider deleted successfully"})
}

// TestSAMLProvider handles POST /admin/saml/providers/:id/test
// @Summary Test SAML Provider
// @Description Test SAML provider configuration (admin only)
// @Tags Admin
// @Produce json
// @Security AdminAuth
// @Param id path string true "Provider ID"
// @Success 200 {object} map[string]interface{} "SAML provider test completed successfully"
// @Router /admin/saml/providers/{id}/test [post]
func (c *AdminController) TestSAMLProvider(ctx *pin.Context) error {
	providerID := ctx.Param("id")
	if providerID == "" {
		return consts.VALIDATION_FAILED
	}

	// Create SAML service
	samlService := services.NewSAMLService(c.authService.GetDB(), c.authService.GetDomainCode())

	// Find provider
	provider, err := samlService.FindSSOProviderByID(ctx.Request.Context(), providerID)
	if err != nil {
		return consts.SSO_PROVIDER_NOT_FOUND
	}

	// Get SAML configuration
	samlConfig, err := samlService.GetSAMLProvider(ctx.Request.Context(), provider)
	if err != nil {
		return ctx.Render(&SAMLTestResponse{
			Success: false,
			Message: "SAML configuration not found",
		})
	}

	// Test certificate
	certService := services.NewCertService("./certs/saml.crt", "./certs/saml.key")
	validation, err := certService.ValidateCertificate()
	if err != nil {
		return ctx.Render(&SAMLTestResponse{
			Success: false,
			Message: "Certificate validation failed: " + err.Error(),
		})
	}

	// Test SAML provider creation
	_, err = samlService.CreateSAMLProvider(ctx.Request.Context(), samlConfig, certService)
	if err != nil {
		return ctx.Render(&SAMLTestResponse{
			Success: false,
			Message: "SAML provider creation failed: " + err.Error(),
		})
	}

	return ctx.Render(&SAMLTestResponse{
		Success: true,
		Message: "SAML provider configuration is valid",
		CertificateInfo: &CertificateInfoResponse{
			ExpiresAt:           validation.ExpiresAt.Format(time.RFC3339),
			IssuedAt:            validation.IssuedAt.Format(time.RFC3339),
			Subject:             validation.Subject,
			Issuer:              validation.Issuer,
			SerialNumber:        validation.SerialNumber,
			DaysUntilExpiration: validation.DaysUntilExpiration(),
		},
	})
}

// ===== Query Builder Helper Functions =====

type QueryBuilder struct {
	query      *gorm.DB
	hasJoin    map[string]bool
	domainCode string
}

func NewQueryBuilder(db *gorm.DB, domainCode string) *QueryBuilder {
	return &QueryBuilder{
		query:      db.Model(&models.User{}).Where("users.domain_code = ?", domainCode),
		hasJoin:    make(map[string]bool),
		domainCode: domainCode,
	}
}

func (qb *QueryBuilder) ensureJoin(table string) {
	if qb.hasJoin[table] {
		return
	}

	switch table {
	case "identities":
		qb.query = qb.query.Joins("LEFT JOIN identities ON identities.user_id = users.id")
		qb.hasJoin[table] = true
	}
}

func (qb *QueryBuilder) Build() *gorm.DB {

	if len(qb.hasJoin) > 0 {
		qb.query = qb.query.Distinct()
	}
	return qb.query
}

func (qb *QueryBuilder) applyFilters(filters map[string]interface{}) {
	for key, value := range filters {
		switch key {
		case "$and":
			if conditions, ok := value.([]interface{}); ok {
				for _, cond := range conditions {
					if condMap, ok := cond.(map[string]interface{}); ok {
						qb.applyFilters(condMap)
					}
				}
			}
		case "$or":
			if conditions, ok := value.([]interface{}); ok {
				if len(conditions) > 0 {

					orConditions := make([]*gorm.DB, 0, len(conditions))
					for _, cond := range conditions {
						if condMap, ok := cond.(map[string]interface{}); ok {

							tempDB := qb.query.Session(&gorm.Session{NewDB: true})
							tempQB := &QueryBuilder{
								query:   tempDB,
								hasJoin: qb.hasJoin,
							}
							tempQB.applyFilters(condMap)
							orConditions = append(orConditions, tempQB.query)
						}
					}

					if len(orConditions) > 0 {
						qb.query = qb.query.Where(orConditions[0])
						for i := 1; i < len(orConditions); i++ {
							qb.query = qb.query.Or(orConditions[i])
						}
					}
				}
			}
		case "$not":
			if condMap, ok := value.(map[string]interface{}); ok {
				notQB := &QueryBuilder{
					query:   qb.query.Session(&gorm.Session{NewDB: true}),
					hasJoin: qb.hasJoin,
				}
				notQB.applyFilters(condMap)
				qb.query = qb.query.Not(notQB.query)
			}
		case "has_identities":

			qb.ensureJoin("identities")
			if value.(bool) {
				qb.query = qb.query.Where("identities.id IS NOT NULL")
			} else {
				qb.query = qb.query.Where("identities.id IS NULL")
			}
		default:
			qb.applyFieldFilter(key, value)
		}
	}
}

func (qb *QueryBuilder) applyFieldFilter(field string, value interface{}) {
	if operators, ok := value.(map[string]interface{}); ok {
		for op, val := range operators {
			qb.applyOperator(field, op, val)
		}
	} else {
		qb.query = qb.query.Where("users."+field+" = ?", value)
	}
}

func (qb *QueryBuilder) applyOperator(field string, operator string, value interface{}) {

	var fullField string
	var isJSONField bool

	if strings.HasPrefix(field, "app_metadata.") {
		jsonPath := strings.TrimPrefix(field, "app_metadata.")
		fullField = fmt.Sprintf("JSON_EXTRACT(raw_app_meta_data, '$.%s')", jsonPath)
		isJSONField = true
	} else if strings.HasPrefix(field, "user_metadata.") {
		jsonPath := strings.TrimPrefix(field, "user_metadata.")
		fullField = fmt.Sprintf("JSON_EXTRACT(raw_user_meta_data, '$.%s')", jsonPath)
		isJSONField = true
	} else {

		fullField = "users." + field
		isJSONField = false
	}

	switch operator {
	case "$eq":
		if isJSONField {
			qb.query = qb.query.Where(fullField+" = ?", fmt.Sprintf("%v", value))
		} else {
			qb.query = qb.query.Where(fullField+" = ?", value)
		}
	case "$ne":
		if isJSONField {
			qb.query = qb.query.Where(fullField+" != ?", fmt.Sprintf("%v", value))
		} else {
			qb.query = qb.query.Where(fullField+" != ?", value)
		}
	case "$in":
		qb.query = qb.query.Where(fullField+" IN ?", value)
	case "$nin":
		qb.query = qb.query.Where(fullField+" NOT IN ?", value)
	case "$contains":
		qb.query = qb.query.Where(fullField+" LIKE ?", "%"+value.(string)+"%")
	case "$startsWith":
		qb.query = qb.query.Where(fullField+" LIKE ?", value.(string)+"%")
	case "$endsWith":
		qb.query = qb.query.Where(fullField+" LIKE ?", "%"+value.(string))
	case "$gt":

		qb.query = qb.query.Where(fullField+" > ?", convertToTime(value))
	case "$gte":
		qb.query = qb.query.Where(fullField+" >= ?", convertToTime(value))
	case "$lt":
		qb.query = qb.query.Where(fullField+" < ?", convertToTime(value))
	case "$lte":
		qb.query = qb.query.Where(fullField+" <= ?", convertToTime(value))
	case "$null":
		if value.(bool) {
			qb.query = qb.query.Where(fullField + " IS NULL")
		} else {
			qb.query = qb.query.Where(fullField + " IS NOT NULL")
		}
	case "$exists":
		if value.(bool) {
			qb.query = qb.query.Where(fullField + " IS NOT NULL")
		} else {
			qb.query = qb.query.Where(fullField + " IS NULL")
		}
	}
}

func convertToTime(value interface{}) interface{} {
	switch v := value.(type) {
	case float64:
		return time.Unix(int64(v), 0)
	case int64:
		return time.Unix(v, 0)
	case int:
		return time.Unix(int64(v), 0)
	default:
		return value
	}
}

func applySorting(query *gorm.DB, sort []string) *gorm.DB {
	for _, s := range sort {

		if !strings.Contains(s, ".") {

			parts := strings.Fields(s)
			if len(parts) > 0 {
				field := parts[0]
				direction := ""
				if len(parts) > 1 {
					direction = " " + strings.Join(parts[1:], " ")
				}
				s = "users." + field + direction
			}
		}
		query = query.Order(s)
	}
	return query
}

// convertModelUserToAdminResponse converts models.User directly to AdminUserResponse
func convertModelUserToAdminResponse(user *models.User) *AdminUserResponse {
	hashid, err := services.GenerateUserHashID(user.ID)
	if err != nil {
		return nil
	}

	response := &AdminUserResponse{
		ID:             hashid,
		EmailConfirmed: user.EmailConfirmedAt != nil,
		PhoneConfirmed: user.PhoneConfirmedAt != nil,
		IsAnonymous:    user.IsAnonymous,
		CreatedAt:      user.CreatedAt.Format(time.RFC3339),
		UpdatedAt:      user.UpdatedAt.Format(time.RFC3339),
	}

	if user.Email != nil {
		response.Email = user.Email
	}
	if user.Phone != nil {
		response.Phone = user.Phone
	}
	if user.BannedUntil != nil {
		bannedUntil := user.BannedUntil.Format(time.RFC3339)
		response.BannedUntil = &bannedUntil
	}
	if user.LastSignInAt != nil {
		lastSignInAt := user.LastSignInAt.Format(time.RFC3339)
		response.LastSignInAt = &lastSignInAt
	}
	if user.RawUserMetaData != nil {
		var userMeta map[string]interface{}
		if err := json.Unmarshal(*user.RawUserMetaData, &userMeta); err == nil {
			response.RawUserMetaData = userMeta
		}
	}
	if user.RawAppMetaData != nil {
		var appMeta map[string]interface{}
		if err := json.Unmarshal(*user.RawAppMetaData, &appMeta); err == nil {
			response.RawAppMetaData = appMeta
		}
	}

	return response
}

// ===== Config Management =====

// GetInstanceConfig handles GET /admin/config
// @Summary Get Instance Config
// @Description Get configuration for the current domain instance
// @Tags Admin
// @Produce json
// @Security AdminAuth
// @Success 200 {object} GetInstanceConfigResponse
// @Router /admin/config [get]
func (c *AdminController) GetInstanceConfig(ctx *pin.Context) error {
	cfg := c.authService.GetConfig()
	domainCode := c.authService.GetDomainCode()

	return ctx.Render(map[string]interface{}{
		"domain_code": domainCode,
		"config":      cfg,
	})
}

// UpdateInstanceConfig handles PUT /admin/config
// @Summary Update Instance Config
// @Description Update configuration for the current domain instance
// @Tags Admin
// @Accept json
// @Produce json
// @Security AdminAuth
// @Param request body UpdateInstanceConfigRequest true "Configuration update"
// @Success 200 {object} UpdateInstanceConfigResponse
// @Router /admin/config [put]
func (c *AdminController) UpdateInstanceConfig(ctx *pin.Context) error {
	var req UpdateInstanceConfigRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		return consts.VALIDATION_FAILED
	}

	err := c.authService.SaveConfig(&req.Config)
	if err != nil {
		return err
	}

	return ctx.Render(map[string]interface{}{
		"message": "Config updated successfully",
		"config":  req.Config,
	})
}
