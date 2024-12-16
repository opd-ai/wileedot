package tlslistener

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/acme/autocert"
)

/**
 * wileedot(wile e.) is a net.Listener implementation with automatic TLS support via ACME/Let's Encrypt.
 * it is named for ACME's most famous customer, wile e. coyote, super genius.
 */

type TLSListener struct {
	mu             sync.RWMutex
	listener       net.Listener
	certManager    *autocert.Manager
	domain         string
	certDir        string
	email          string
	allowedDomains []string
}

type Config struct {
	// Domain is the primary domain for the certificate
	Domain string
	// AllowedDomains is a list of additional domains to allow (optional)
	AllowedDomains []string
	// CertDir is the directory to store certificates
	CertDir string
	// Email is the contact email for Let's Encrypt
	Email string
	// BaseListener is an optional existing listener to wrap with TLS
	// If nil, a new TCP listener on :443 will be created
	BaseListener net.Listener
}

// New creates a new TLSListener with the given configuration
func New(cfg Config) (*TLSListener, error) {
	if cfg.Domain == "" {
		return nil, errors.New("domain is required")
	}
	if cfg.CertDir == "" {
		return nil, errors.New("certificate directory is required")
	}

	tl := &TLSListener{
		domain:         cfg.Domain,
		certDir:        cfg.CertDir,
		email:          cfg.Email,
		allowedDomains: append([]string{cfg.Domain}, cfg.AllowedDomains...),
	}

	if err := tl.setup(cfg.BaseListener); err != nil {
		return nil, errors.Wrap(err, "failed to setup TLS listener")
	}

	// Start certificate renewal goroutine
	go tl.renewalRoutine()

	return tl, nil
}

func (tl *TLSListener) setup(baseListener net.Listener) error {
	// Create the autocert manager
	certManager := &autocert.Manager{
		Cache:      autocert.DirCache(tl.certDir),
		Prompt:     autocert.AcceptTOS,
		Email:      tl.email,
		HostPolicy: autocert.HostWhitelist(tl.allowedDomains...),
	}

	// Create TLS config
	tlsConfig := certManager.TLSConfig()
	tlsConfig.MinVersion = tls.VersionTLS12

	var listener net.Listener
	var err error

	if baseListener == nil {
		// Create a new TCP listener if none provided
		listener, err = tls.Listen("tcp", ":443", tlsConfig)
		if err != nil {
			return errors.Wrap(err, "failed to create TLS listener")
		}
	} else {
		// Wrap existing listener with TLS
		listener = tls.NewListener(baseListener, tlsConfig)
	}

	tl.mu.Lock()
	tl.listener = listener
	tl.certManager = certManager
	tl.mu.Unlock()

	return nil
}

// Implementation of net.Listener interface

func (tl *TLSListener) Accept() (net.Conn, error) {
	tl.mu.RLock()
	listener := tl.listener
	tl.mu.RUnlock()

	if listener == nil {
		return nil, errors.New("listener is closed")
	}
	return listener.Accept()
}

func (tl *TLSListener) Close() error {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	if tl.listener == nil {
		return nil
	}

	err := tl.listener.Close()
	tl.listener = nil
	return err
}

func (tl *TLSListener) Addr() net.Addr {
	tl.mu.RLock()
	defer tl.mu.RUnlock()

	if tl.listener == nil {
		return nil
	}
	return tl.listener.Addr()
}

// certInfo holds certificate timing information
type certInfo struct {
	NotBefore time.Time
	NotAfter  time.Time
}

// getCertInfo extracts timing information from the current certificate
func (tl *TLSListener) getCertInfo() (*certInfo, error) {
	tl.mu.RLock()
	manager := tl.certManager
	tl.mu.RUnlock()

	if manager == nil {
		return nil, errors.New("cert manager is not initialized")
	}

	// Get current certificate
	cert, err := manager.GetCertificate(&tls.ClientHelloInfo{
		ServerName: tl.domain,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to get current certificate")
	}

	// Extract leaf certificate
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse certificate")
	}

	return &certInfo{
		NotBefore: leaf.NotBefore,
		NotAfter:  leaf.NotAfter,
	}, nil
}

// shouldRenew checks if the certificate should be renewed
func (tl *TLSListener) shouldRenew() (bool, error) {
	info, err := tl.getCertInfo()
	if err != nil {
		return false, err
	}

	now := time.Now()

	// Check if it's been at least 2 months since the last renewal
	twoMonthsAgo := now.AddDate(0, -2, 0)
	if info.NotBefore.After(twoMonthsAgo) {
		return false, nil
	}

	// As a safety check, also renew if we're within 30 days of expiration
	thirtyDaysFromNow := now.AddDate(0, 0, 30)
	if thirtyDaysFromNow.After(info.NotAfter) {
		return true, nil
	}

	return true, nil
}

// renewalRoutine handles periodic certificate renewal checks
func (tl *TLSListener) renewalRoutine() {
	ticker := time.NewTicker(24 * time.Hour) // Check daily
	defer ticker.Stop()

	for range ticker.C {
		shouldRenew, err := tl.shouldRenew()
		if err != nil {
			logf("Failed to check certificate renewal status: %v", err)
			continue
		}

		if shouldRenew {
			if err := tl.renewCertificates(); err != nil {
				logf("Failed to renew certificates: %v", err)
			} else {
				logf("Successfully renewed certificates for %s", tl.domain)
			}
		}
	}
}

// renewCertificates forces certificate renewal
func (tl *TLSListener) renewCertificates() error {
	tl.mu.RLock()
	manager := tl.certManager
	tl.mu.RUnlock()

	if manager == nil {
		return errors.New("cert manager is not initialized")
	}

	// Force renewal by getting a new certificate
	_, err := manager.GetCertificate(&tls.ClientHelloInfo{
		ServerName: tl.domain,
	})

	return err
}

// logf is a helper function for logging
// In production, you might want to replace this with a proper logger
func logf(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
}
