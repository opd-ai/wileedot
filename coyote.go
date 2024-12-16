package tlslistener

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/acme/autocert"
)

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

// renewalRoutine handles periodic certificate renewal checks
func (tl *TLSListener) renewalRoutine() {
	ticker := time.NewTicker(2 * 30 * 24 * time.Hour) // ~2 months
	defer ticker.Stop()

	for range ticker.C {
		if err := tl.renewCertificates(); err != nil {
			fmt.Printf("Failed to renew certificates: %v\n", err)
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
