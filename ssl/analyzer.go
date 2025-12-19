package ssl

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

type CertificateInfo struct {
	Domain             string
	Issuer             string
	Subject            string
	ValidFrom          time.Time
	ValidTo            time.Time
	SerialNumber       string
	SignatureAlgorithm string
	PublicKeyAlgorithm string
	KeySize            int
	IsValid            bool
	DaysUntilExpiry    int
	WeakCiphers        []string
	TLSVersion         string
}

type Analyzer struct {
	Target  string
	Timeout time.Duration
}

func NewAnalyzer(target string) *Analyzer {
	return &Analyzer{
		Target:  target,
		Timeout: 10 * time.Second,
	}
}

func (a *Analyzer) Analyze() (*CertificateInfo, error) {
	host, _, err := net.SplitHostPort(a.Target)
	if err != nil {
		return nil, fmt.Errorf("invalid target format: %w", err)
	}

	conn, err := net.DialTimeout("tcp", a.Target, a.Timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	config := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	}

	tlsConn := tls.Client(conn, config)
	err = tlsConn.Handshake()
	if err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	cert := state.PeerCertificates[0]
	now := time.Now()

	info := &CertificateInfo{
		Domain:             a.Target,
		Issuer:             cert.Issuer.String(),
		Subject:            cert.Subject.String(),
		ValidFrom:          cert.NotBefore,
		ValidTo:            cert.NotAfter,
		SerialNumber:       cert.SerialNumber.String(),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		IsValid:            now.After(cert.NotBefore) && now.Before(cert.NotAfter),
		DaysUntilExpiry:    int(time.Until(cert.NotAfter).Hours() / 24),
		TLSVersion:         getTLSVersion(state.Version),
	}

	info.KeySize = 2048

	info.WeakCiphers = a.detectWeakCiphers(state)

	return info, nil
}

func (a *Analyzer) detectWeakCiphers(state tls.ConnectionState) []string {
	var weak []string

	weakCipherSuites := map[uint16]string{
		0x0005: "TLS_RSA_WITH_RC4_128_SHA",
		0x000a: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
		0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	}

	if state.CipherSuite != 0 {
		if name, ok := weakCipherSuites[state.CipherSuite]; ok {
			weak = append(weak, name)
		}
	}

	return weak
}

func getTLSVersion(version uint16) string {
	versions := map[uint16]string{
		0x0301: "TLS 1.0",
		0x0302: "TLS 1.1",
		0x0303: "TLS 1.2",
		0x0304: "TLS 1.3",
	}
	if v, ok := versions[version]; ok {
		return v
	}
	return "Unknown"
}
