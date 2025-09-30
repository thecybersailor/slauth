package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// CertService handles SAML certificate management
type CertService struct {
	certPath string
	keyPath  string
}

// CertificateInfo contains certificate details
type CertificateInfo struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
	CertPEM     []byte
	KeyPEM      []byte
}

// NewCertService creates a new certificate service
func NewCertService(certPath, keyPath string) *CertService {
	return &CertService{
		certPath: certPath,
		keyPath:  keyPath,
	}
}

// LoadCertificate loads certificate and private key from files
func (cs *CertService) LoadCertificate() (*CertificateInfo, error) {
	// Check if files exist
	if !cs.certificateExists() {
		return nil, fmt.Errorf("certificate files not found: %s, %s", cs.certPath, cs.keyPath)
	}

	// Load certificate and key pair
	keyPair, err := tls.LoadX509KeyPair(cs.certPath, cs.keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate pair: %w", err)
	}

	// Parse certificate
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Read PEM files
	certPEM, err := os.ReadFile(cs.certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	keyPEM, err := os.ReadFile(cs.keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	return &CertificateInfo{
		Certificate: keyPair.Leaf,
		PrivateKey:  keyPair.PrivateKey.(*rsa.PrivateKey),
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
	}, nil
}

// GenerateSelfSignedCert generates a self-signed certificate for SAML SP
func (cs *CertService) GenerateSelfSignedCert(entityID string, validDays int) error {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"slauth"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			CommonName:    entityID,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Duration(validDays) * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{},
		DNSNames:    []string{},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Ensure directory exists
	if err := cs.ensureDirectoryExists(); err != nil {
		return err
	}

	// Save certificate
	certOut, err := os.Create(cs.certPath)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %w", err)
	}
	defer func() {
		if closeErr := certOut.Close(); closeErr != nil {
			err = closeErr
		}
	}()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Save private key
	keyOut, err := os.Create(cs.keyPath)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer func() {
		if closeErr := keyOut.Close(); closeErr != nil {
			err = closeErr
		}
	}()

	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	return nil
}

// ValidateCertificate validates the certificate and checks expiration
func (cs *CertService) ValidateCertificate() (*CertificateValidation, error) {
	certInfo, err := cs.LoadCertificate()
	if err != nil {
		return nil, err
	}

	validation := &CertificateValidation{
		IsValid:      true,
		ExpiresAt:    certInfo.Certificate.NotAfter,
		IssuedAt:     certInfo.Certificate.NotBefore,
		Subject:      certInfo.Certificate.Subject.String(),
		Issuer:       certInfo.Certificate.Issuer.String(),
		SerialNumber: certInfo.Certificate.SerialNumber.String(),
	}

	// Check if certificate is expired
	now := time.Now()
	if now.After(certInfo.Certificate.NotAfter) {
		validation.IsValid = false
		validation.Errors = append(validation.Errors, "certificate has expired")
	}

	// Check if certificate is not yet valid
	if now.Before(certInfo.Certificate.NotBefore) {
		validation.IsValid = false
		validation.Errors = append(validation.Errors, "certificate is not yet valid")
	}

	// Check if certificate expires soon (within 30 days)
	if now.Add(30 * 24 * time.Hour).After(certInfo.Certificate.NotAfter) {
		validation.Warnings = append(validation.Warnings, "certificate expires within 30 days")
	}

	// Validate key usage
	if certInfo.Certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		validation.Warnings = append(validation.Warnings, "certificate does not have digital signature usage")
	}

	return validation, nil
}

// CertificateExists checks if certificate files exist
func (cs *CertService) certificateExists() bool {
	_, certErr := os.Stat(cs.certPath)
	_, keyErr := os.Stat(cs.keyPath)
	return certErr == nil && keyErr == nil
}

// ensureDirectoryExists creates the directory for certificate files if it doesn't exist
func (cs *CertService) ensureDirectoryExists() error {
	certDir := filepath.Dir(cs.certPath)
	keyDir := filepath.Dir(cs.keyPath)

	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("failed to create certificate directory: %w", err)
	}

	if certDir != keyDir {
		if err := os.MkdirAll(keyDir, 0755); err != nil {
			return fmt.Errorf("failed to create key directory: %w", err)
		}
	}

	return nil
}

// GetCertificatePaths returns the configured certificate and key paths
func (cs *CertService) GetCertificatePaths() (string, string) {
	return cs.certPath, cs.keyPath
}

// CertificateValidation contains certificate validation results
type CertificateValidation struct {
	IsValid      bool      `json:"is_valid"`
	ExpiresAt    time.Time `json:"expires_at"`
	IssuedAt     time.Time `json:"issued_at"`
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	SerialNumber string    `json:"serial_number"`
	Errors       []string  `json:"errors,omitempty"`
	Warnings     []string  `json:"warnings,omitempty"`
}

// DaysUntilExpiration returns the number of days until certificate expiration
func (cv *CertificateValidation) DaysUntilExpiration() int {
	duration := time.Until(cv.ExpiresAt)
	return int(duration.Hours() / 24)
}

// IsExpiringSoon returns true if certificate expires within the specified days
func (cv *CertificateValidation) IsExpiringSoon(days int) bool {
	return cv.DaysUntilExpiration() <= days
}
