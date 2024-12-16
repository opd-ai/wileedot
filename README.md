# wileedot - Automated TLS Listener for Go

`wileedot` (named after ACME's most famous customer, Wile E. Coyote) is a drop-in TLS listener implementation that automatically handles certificate management through Let's Encrypt. It provides seamless TLS support for your Go web services with minimal configuration.

## Features

- 🔒 Automatic TLS certificate provisioning via Let's Encrypt
- 🔄 Automatic certificate renewal (every 2 months)
- 🔌 Works with existing `net.Listener` implementations
- 🎯 Support for multiple domains
- 💾 Persistent certificate storage
- 🔐 TLS 1.2+ enforcement
- 🧵 Thread-safe operations

## Installation

```bash
go get github.com/opd-ai/wileedot
```

## Quick Start

```go
package main

import (
    "log"
    "net/http"
    "github.com/opd-ai/wileedot"
)

func main() {
    // Configure the TLS listener
    config := tlslistener.Config{
        Domain:  "example.com",
        CertDir: "/etc/certs",
        Email:   "admin@example.com",
    }

    // Create the listener
    listener, err := tlslistener.New(config)
    if err != nil {
        log.Fatal(err)
    }
    defer listener.Close()

    // Use with standard http server
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Hello, TLS!"))
    })

    log.Fatal(http.Serve(listener, nil))
}
```

## Advanced Usage

### Custom Base Listener

```go
baseListener, err := net.Listen("tcp", ":8443")
if err != nil {
    log.Fatal(err)
}

config := tlslistener.Config{
    Domain:       "example.com",
    CertDir:      "/etc/certs",
    Email:        "admin@example.com",
    BaseListener: baseListener,
}

listener, err := tlslistener.New(config)
```

### Multiple Domains

```go
config := tlslistener.Config{
    Domain:         "example.com",
    AllowedDomains: []string{"www.example.com", "api.example.com"},
    CertDir:        "/etc/certs",
    Email:          "admin@example.com",
}
```

### Certificate Monitoring

```go
info, err := listener.GetCertInfo()
if err != nil {
    log.Fatal(err)
}

log.Printf("Certificate valid from %v to %v", 
    info.NotBefore, 
    info.NotAfter)
```

## Configuration Options

| Option | Description | Required | Default |
|--------|-------------|----------|---------|
| Domain | Primary domain for the certificate | Yes | - |
| AllowedDomains | Additional domains for the certificate | No | [] |
| CertDir | Directory to store certificates | Yes | - |
| Email | Contact email for Let's Encrypt | Yes | - |
| BaseListener | Existing listener to wrap with TLS | No | `:443` |

## Requirements

- Go 1.16 or higher
- Write access to the certificate directory
- Port 80 accessible for ACME challenges
- Port 443 accessible for TLS (if using default listener)

## Important Notes

1. **Certificate Directory**: Must be persistent and writable
2. **ACME Challenges**: Port 80 must be accessible for domain validation
3. **Rate Limits**: Let's Encrypt has [rate limits](https://letsencrypt.org/docs/rate-limits/)
4. **Production Usage**: Consider implementing proper logging and monitoring

## Error Handling

The listener includes comprehensive error handling for common scenarios:

- Certificate initialization failures
- Renewal errors
- Network issues
- Invalid configurations

Errors are wrapped using `github.com/pkg/errors` for better context.

## Security Considerations

- Enforces TLS 1.2 minimum
- Automatic certificate renewal
- Secure storage of private keys
- Domain validation
- Thread-safe operations

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

[MIT License](LICENSE)

## Acknowledgments

- Let's Encrypt for providing free certificates
- golang.org/x/crypto/acme/autocert for ACME implementation
- ACME Corporation for inspiring the name through their valued customer

## Support

For issues and feature requests, please use the GitHub issue tracker.