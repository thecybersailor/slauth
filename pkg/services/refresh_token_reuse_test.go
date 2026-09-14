package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/thecybersailor/slauth/pkg/consts"
	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/types"
	"gorm.io/gorm"
)

func TestRefreshTokenReuseIntervalReturnsRotatedChildToken(t *testing.T) {
	db := newSessionMetaTokenTestDB(t)
	service := NewAuthServiceImpl(db, newSessionMetaTokenTestSecretsProvider(t), "tenant_refresh_reuse")
	phone := "+8618616977999"
	user, err := service.GetUserService().CreateUserWithSource(context.Background(), &UserCreateOptions{
		Phone: &phone,
	}, UserCreatedSourceAdmin, nil, nil)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	session, _, originalRefreshToken, _, err := service.CreateSession(
		context.Background(),
		user,
		types.AALLevel1,
		[]string{"sms"},
		"test",
		"127.0.0.1",
	)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	var original models.RefreshToken
	if err := db.Where("token = ?", originalRefreshToken).First(&original).Error; err != nil {
		t.Fatalf("load original refresh token: %v", err)
	}

	_, _, rotatedRefreshToken, _, err := service.RefreshSessionWithRefreshToken(
		context.Background(),
		user,
		&original,
		false,
		types.AALLevel1,
		[]string{"refresh_token"},
		"test",
		"127.0.0.1",
	)
	if err != nil {
		t.Fatalf("rotate refresh token: %v", err)
	}
	if rotatedRefreshToken == originalRefreshToken {
		t.Fatalf("expected rotated refresh token to differ from original")
	}

	var rotatedOriginal models.RefreshToken
	if err := db.First(&rotatedOriginal, original.ID).Error; err != nil {
		t.Fatalf("reload original refresh token: %v", err)
	}
	if !rotatedOriginal.Revoked {
		t.Fatalf("expected original refresh token to be revoked")
	}

	resolved, reused, err := service.ResolveRefreshToken(context.Background(), originalRefreshToken)
	if err != nil {
		t.Fatalf("resolve reused refresh token: %v", err)
	}
	if !reused {
		t.Fatalf("expected reused refresh token resolution")
	}
	if resolved.Token != rotatedRefreshToken {
		t.Fatalf("expected reused token %q, got %q", rotatedRefreshToken, resolved.Token)
	}

	reusedSession, _, reusedRefreshToken, _, err := service.RefreshSessionWithRefreshToken(
		context.Background(),
		user,
		resolved,
		reused,
		types.AALLevel1,
		[]string{"refresh_token"},
		"test",
		"127.0.0.1",
	)
	if err != nil {
		t.Fatalf("reuse rotated refresh token: %v", err)
	}
	if reusedSession.ID != session.ID {
		t.Fatalf("expected reused session %d, got %d", session.ID, reusedSession.ID)
	}
	if reusedRefreshToken != rotatedRefreshToken {
		t.Fatalf("expected refresh token reuse to return %q, got %q", rotatedRefreshToken, reusedRefreshToken)
	}

	var childCount int64
	if err := db.Model(&models.RefreshToken{}).Where("parent = ?", original.ID).Count(&childCount).Error; err != nil {
		t.Fatalf("count child refresh tokens: %v", err)
	}
	if childCount != 1 {
		t.Fatalf("expected exactly one rotated child token, got %d", childCount)
	}
}

func TestRefreshTokenReuseIntervalRejectsOldTokenAfterWindow(t *testing.T) {
	db := newSessionMetaTokenTestDB(t)
	service := NewAuthServiceImpl(db, newSessionMetaTokenTestSecretsProvider(t), "tenant_refresh_reuse_expired")
	phone := "+8618616977998"
	user, err := service.GetUserService().CreateUserWithSource(context.Background(), &UserCreateOptions{
		Phone: &phone,
	}, UserCreatedSourceAdmin, nil, nil)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	_, _, originalRefreshToken, _, err := service.CreateSession(
		context.Background(),
		user,
		types.AALLevel1,
		[]string{"sms"},
		"test",
		"127.0.0.1",
	)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	var original models.RefreshToken
	if err := db.Where("token = ?", originalRefreshToken).First(&original).Error; err != nil {
		t.Fatalf("load original refresh token: %v", err)
	}

	if _, _, _, _, err := service.RefreshSessionWithRefreshToken(
		context.Background(),
		user,
		&original,
		false,
		types.AALLevel1,
		[]string{"refresh_token"},
		"test",
		"127.0.0.1",
	); err != nil {
		t.Fatalf("rotate refresh token: %v", err)
	}

	expiredUpdatedAt := time.Now().Add(-time.Duration(service.GetConfig().SessionConfig.RefreshTokenReuseInterval+1) * time.Second)
	if err := db.Model(&models.RefreshToken{}).
		Where("id = ?", original.ID).
		Update("updated_at", expiredUpdatedAt).Error; err != nil {
		t.Fatalf("expire reuse interval: %v", err)
	}

	_, _, err = service.ResolveRefreshToken(context.Background(), originalRefreshToken)
	if !errors.Is(err, consts.REFRESH_TOKEN_NOT_FOUND) {
		t.Fatalf("expected refresh_token_not_found after reuse window, got %v", err)
	}
}

func TestRefreshTokenReuseIntervalDisabledRejectsOldToken(t *testing.T) {
	db := newSessionMetaTokenTestDB(t)
	service := NewAuthServiceImpl(db, newSessionMetaTokenTestSecretsProvider(t), "tenant_refresh_reuse_disabled")
	service.GetConfig().SessionConfig.RefreshTokenReuseInterval = 0
	user, originalRefreshToken, original := createRefreshTokenReuseFixture(t, db, service, "+8618616977997")

	if _, _, _, _, err := service.RefreshSessionWithRefreshToken(
		context.Background(),
		user,
		original,
		false,
		types.AALLevel1,
		[]string{"refresh_token"},
		"test",
		"127.0.0.1",
	); err != nil {
		t.Fatalf("rotate refresh token: %v", err)
	}

	_, _, err := service.ResolveRefreshToken(context.Background(), originalRefreshToken)
	if !errors.Is(err, consts.REFRESH_TOKEN_NOT_FOUND) {
		t.Fatalf("expected refresh_token_not_found with disabled reuse interval, got %v", err)
	}
}

func TestRefreshTokenReuseIntervalRejectsRevokedTokenWithoutChild(t *testing.T) {
	db := newSessionMetaTokenTestDB(t)
	service := NewAuthServiceImpl(db, newSessionMetaTokenTestSecretsProvider(t), "tenant_refresh_reuse_no_child")
	_, originalRefreshToken, _ := createRefreshTokenReuseFixture(t, db, service, "+8618616977996")

	if err := service.RevokeRefreshToken(context.Background(), originalRefreshToken); err != nil {
		t.Fatalf("revoke refresh token: %v", err)
	}

	_, _, err := service.ResolveRefreshToken(context.Background(), originalRefreshToken)
	if !errors.Is(err, consts.REFRESH_TOKEN_NOT_FOUND) {
		t.Fatalf("expected refresh_token_not_found without reusable child, got %v", err)
	}
}

func TestResolveRefreshTokenReturnsSessionExpiredForActiveToken(t *testing.T) {
	db := newSessionMetaTokenTestDB(t)
	service := NewAuthServiceImpl(db, newSessionMetaTokenTestSecretsProvider(t), "tenant_refresh_reuse_active_expired")
	_, originalRefreshToken, original := createRefreshTokenReuseFixture(t, db, service, "+8618616977995")

	expiredAt := time.Now().Add(-time.Minute)
	if err := db.Model(&models.Session{}).
		Where("id = ?", original.SessionID).
		Update("not_after", expiredAt).Error; err != nil {
		t.Fatalf("expire session: %v", err)
	}

	_, _, err := service.ResolveRefreshToken(context.Background(), originalRefreshToken)
	if !errors.Is(err, consts.SESSION_EXPIRED) {
		t.Fatalf("expected session_expired for active refresh token, got %v", err)
	}
}

func TestResolveRefreshTokenReturnsSessionExpiredForReusableChild(t *testing.T) {
	db := newSessionMetaTokenTestDB(t)
	service := NewAuthServiceImpl(db, newSessionMetaTokenTestSecretsProvider(t), "tenant_refresh_reuse_child_expired")
	user, originalRefreshToken, original := createRefreshTokenReuseFixture(t, db, service, "+8618616977994")

	if _, _, _, _, err := service.RefreshSessionWithRefreshToken(
		context.Background(),
		user,
		original,
		false,
		types.AALLevel1,
		[]string{"refresh_token"},
		"test",
		"127.0.0.1",
	); err != nil {
		t.Fatalf("rotate refresh token: %v", err)
	}

	expiredAt := time.Now().Add(-time.Minute)
	if err := db.Model(&models.Session{}).
		Where("id = ?", original.SessionID).
		Update("not_after", expiredAt).Error; err != nil {
		t.Fatalf("expire session: %v", err)
	}

	_, _, err := service.ResolveRefreshToken(context.Background(), originalRefreshToken)
	if !errors.Is(err, consts.SESSION_EXPIRED) {
		t.Fatalf("expected session_expired for reusable child refresh token, got %v", err)
	}
}

func TestRefreshSessionWithRefreshTokenReusesExistingChildAndRevokesParent(t *testing.T) {
	db := newSessionMetaTokenTestDB(t)
	service := NewAuthServiceImpl(db, newSessionMetaTokenTestSecretsProvider(t), "tenant_refresh_reuse_existing_child")
	user, _, original := createRefreshTokenReuseFixture(t, db, service, "+8618616977993")
	childTokenString, err := service.jwtService.GenerateRefreshToken()
	if err != nil {
		t.Fatalf("generate child refresh token: %v", err)
	}
	child := &models.RefreshToken{
		Token:      childTokenString,
		UserID:     original.UserID,
		SessionID:  original.SessionID,
		InstanceId: service.GetInstanceId(),
		Revoked:    false,
		Parent:     &original.ID,
	}
	if err := db.Create(child).Error; err != nil {
		t.Fatalf("create child refresh token: %v", err)
	}

	_, _, returnedRefreshToken, _, err := service.RefreshSessionWithRefreshToken(
		context.Background(),
		user,
		original,
		false,
		types.AALLevel1,
		[]string{"refresh_token"},
		"test",
		"127.0.0.1",
	)
	if err != nil {
		t.Fatalf("refresh with existing child token: %v", err)
	}
	if returnedRefreshToken != childTokenString {
		t.Fatalf("expected existing child refresh token %q, got %q", childTokenString, returnedRefreshToken)
	}

	var revokedParent models.RefreshToken
	if err := db.First(&revokedParent, original.ID).Error; err != nil {
		t.Fatalf("reload parent refresh token: %v", err)
	}
	if !revokedParent.Revoked {
		t.Fatalf("expected parent refresh token to be revoked")
	}
}

func TestRefreshSessionReusesExistingChildAfterParentConflict(t *testing.T) {
	db := newSessionMetaTokenTestDB(t)
	service := NewAuthServiceImpl(db, newSessionMetaTokenTestSecretsProvider(t), "tenant_refresh_reuse_conflict")
	user, _, original := createRefreshTokenReuseFixture(t, db, service, "+8618616977992")
	childTokenString, err := service.jwtService.GenerateRefreshToken()
	if err != nil {
		t.Fatalf("generate child refresh token: %v", err)
	}
	if err := db.Create(&models.RefreshToken{
		Token:      childTokenString,
		UserID:     original.UserID,
		SessionID:  original.SessionID,
		InstanceId: service.GetInstanceId(),
		Revoked:    false,
		Parent:     &original.ID,
	}).Error; err != nil {
		t.Fatalf("create child refresh token: %v", err)
	}

	_, _, returnedRefreshToken, _, err := service.refreshSession(
		context.Background(),
		user,
		original.SessionID,
		types.AALLevel1,
		[]string{"refresh_token"},
		"test",
		"127.0.0.1",
		&original.ID,
		"",
	)
	if err != nil {
		t.Fatalf("refresh after parent conflict: %v", err)
	}
	if returnedRefreshToken != childTokenString {
		t.Fatalf("expected existing child refresh token %q, got %q", childTokenString, returnedRefreshToken)
	}
}

func TestRevokeRefreshTokenReturnsNotFound(t *testing.T) {
	db := newSessionMetaTokenTestDB(t)
	service := NewAuthServiceImpl(db, newSessionMetaTokenTestSecretsProvider(t), "tenant_refresh_reuse_revoke_missing")

	err := service.RevokeRefreshToken(context.Background(), "missing-refresh-token")
	if !errors.Is(err, consts.REFRESH_TOKEN_NOT_FOUND) {
		t.Fatalf("expected refresh_token_not_found revoking missing token, got %v", err)
	}
}

func createRefreshTokenReuseFixture(t *testing.T, db *gorm.DB, service *AuthServiceImpl, phone string) (*User, string, *models.RefreshToken) {
	t.Helper()
	user, err := service.GetUserService().CreateUserWithSource(context.Background(), &UserCreateOptions{
		Phone: &phone,
	}, UserCreatedSourceAdmin, nil, nil)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	_, _, originalRefreshToken, _, err := service.CreateSession(
		context.Background(),
		user,
		types.AALLevel1,
		[]string{"sms"},
		"test",
		"127.0.0.1",
	)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	var original models.RefreshToken
	if err := db.Where("token = ?", originalRefreshToken).First(&original).Error; err != nil {
		t.Fatalf("load original refresh token: %v", err)
	}

	return user, originalRefreshToken, &original
}
