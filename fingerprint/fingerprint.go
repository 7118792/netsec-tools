package fingerprint

import (
	"fmt"
	"net"
	"strings"
	"time"
)

type ServiceInfo struct {
	Service    string
	Version    string
	Banner     string
	OS         string
	Protocol   string
	Confidence int
}

type Fingerprinter struct {
	Timeout time.Duration
}

func NewFingerprinter() *Fingerprinter {
	return &Fingerprinter{
		Timeout: 5 * time.Second,
	}
}

func (f *Fingerprinter) Fingerprint(target string, port int) (*ServiceInfo, error) {
	address := net.JoinHostPort(target, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", address, f.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	info := &ServiceInfo{
		Protocol: "tcp",
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err == nil && n > 0 {
		banner := string(buffer[:n])
		info.Banner = strings.TrimSpace(banner)
		info.Service, info.Version = f.identifyService(info.Banner, port)
		info.Confidence = f.calculateConfidence(info.Banner, port)
	} else {
		info.Service, info.Version = f.identifyService("", port)
		info.Confidence = f.calculateConfidence("", port)
	}

	return info, nil
}

func (f *Fingerprinter) identifyService(banner string, port int) (string, string) {
	bannerLower := strings.ToLower(banner)

	patterns := map[string][]string{
		"ssh":      {"openssh", "ssh-2.0", "dropbear"},
		"ftp":      {"220", "vsftpd", "proftpd", "pure-ftpd"},
		"http":     {"http/1", "server:", "apache", "nginx", "iis"},
		"smtp":     {"220", "esmtp", "postfix", "sendmail"},
		"pop3":     {"+ok", "pop3"},
		"imap":     {"* ok", "imap"},
		"mysql":    {"mysql", "mariadb"},
		"postgres": {"postgresql"},
		"telnet":   {"login:", "password:"},
	}

	for service, keywords := range patterns {
		for _, keyword := range keywords {
			if strings.Contains(bannerLower, keyword) {
				version := f.extractVersion(banner)
				return service, version
			}
		}
	}

	defaultServices := map[int]string{
		22:   "ssh",
		21:   "ftp",
		80:   "http",
		443:  "https",
		25:   "smtp",
		110:  "pop3",
		143:  "imap",
		135:  "msrpc",
		139:  "netbios-ssn",
		445:  "microsoft-ds",
		3389: "rdp",
		3306: "mysql",
		5432: "postgresql",
	}

	if service, ok := defaultServices[port]; ok {
		return service, "unknown"
	}

	return "unknown", "unknown"
}

func (f *Fingerprinter) extractVersion(banner string) string {
	parts := strings.Fields(banner)
	for i, part := range parts {
		if strings.Contains(part, "/") || strings.Contains(part, "v") {
			if i+1 < len(parts) {
				return parts[i+1]
			}
			return part
		}
	}
	return "unknown"
}

func (f *Fingerprinter) calculateConfidence(banner string, port int) int {
	if len(banner) > 10 {
		return 80
	}
	if port < 1024 {
		if banner != "" {
			return 70
		}
		return 50
	}
	if banner != "" {
		return 60
	}
	return 30
}

func (f *Fingerprinter) OSDetection(target string) (string, error) {
	return "unknown", nil
}
