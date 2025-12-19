# Network Security Tools

Enterprise-grade network security framework engineered in Go. This toolkit represents decades of accumulated knowledge in penetration testing, network reconnaissance, and security assessment methodologies. Built for professionals who demand precision, performance, and comprehensive network intelligence.

## Capabilities

The following modules constitute a complete network security assessment framework:

- **Port Scanner**: High-performance concurrent TCP/UDP port enumeration with intelligent service detection and banner grabbing
- **Packet Capture**: Low-level network traffic interception and deep packet inspection capabilities
- **Subdomain Enumeration**: Advanced DNS reconnaissance with multiple enumeration vectors and brute-force capabilities
- **SSL/TLS Analyzer**: Comprehensive certificate chain validation, cipher suite analysis, and security posture assessment
- **DNS Tools**: Complete DNS enumeration suite including record type queries, reverse lookups, and zone transfer attempts
- **Service Fingerprinting**: Sophisticated service identification with version detection and operating system fingerprinting
- **Network Mapper**: Automated network topology discovery with host enumeration and service mapping

## Installation

```bash
go mod download
go build -o netsec-tools ./cmd/main.go
```

Windows compilation produces `netsec-tools.exe`. Execute with:
```bash
.\netsec-tools.exe
```

## Implementation

### Port Scanner
```go
scanner := scanner.NewPortScanner("192.168.1.1", 1, 65535, 100)
results := scanner.Scan()
```

### Packet Capture
```go
capture := capture.NewPacketCapture("eth0")
capture.Start()
packets := capture.CapturePackets(100)
```

### Subdomain Enumeration
```go
enumerator := subdomain.NewEnumerator("example.com")
subdomains := enumerator.Enumerate()
```

### SSL/TLS Analyzer
```go
analyzer := ssl.NewAnalyzer("example.com:443")
cert := analyzer.Analyze()
```

## Architecture

- `scanner/` - Concurrent port scanning engine with configurable thread pools
- `capture/` - Raw packet capture and protocol analysis
- `subdomain/` - Multi-technique subdomain discovery engine
- `ssl/` - TLS handshake analysis and certificate validation
- `dns/` - Comprehensive DNS query and enumeration framework
- `fingerprint/` - Service identification and version detection
- `mapper/` - Network host discovery and topology mapping

## Prerequisites

- Go 1.21 or later
- Elevated privileges (root/Administrator) required for packet capture operations
- Network connectivity and appropriate authorization for target scanning

