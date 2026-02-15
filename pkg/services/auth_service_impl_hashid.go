package services

// GetHashIDService returns the instance-scoped hashid service.
// NOTE: This is intentionally not part of the AuthService interface to avoid a breaking change.
func (s *AuthServiceImpl) GetHashIDService() *HashIDService {
	if s == nil {
		return nil
	}
	return s.hashIDService
}

