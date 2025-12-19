package main

import (
	"fmt"
	"runtime"

	"netsec-tools/capture"
	"netsec-tools/dns"
	"netsec-tools/fingerprint"
	"netsec-tools/mapper"
	"netsec-tools/scanner"
	"netsec-tools/ssl"
	"netsec-tools/subdomain"
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	fmt.Println("Network Security Tools - Example Usage")
	fmt.Printf("Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)

	fmt.Println("\n=== Port Scanner ===")
	portScanner := scanner.NewPortScanner("127.0.0.1", 1, 1000, 50)
	results := portScanner.Scan()
	if len(results) > 0 {
		fmt.Printf("Found %d open ports:\n", len(results))
		for _, result := range results {
			fmt.Printf("  Port %d: %s (%s)", result.Port, result.State, result.Service)
			if result.Banner != "" {
				fmt.Printf(" - Banner: %s", result.Banner[:min(50, len(result.Banner))])
			}
			fmt.Println()
		}
	} else {
		fmt.Println("No open ports found")
	}

	fmt.Println("\n=== Subdomain Enumeration ===")
	enumerator := subdomain.NewEnumerator("example.com")
	subdomains := enumerator.Enumerate()
	if len(subdomains) > 0 {
		fmt.Printf("Found %d subdomains:\n", len(subdomains))
		for i, sub := range subdomains {
			if i < 10 {
				fmt.Printf("  %s\n", sub)
			} else {
				fmt.Printf("  ... and %d more\n", len(subdomains)-10)
				break
			}
		}
	} else {
		fmt.Println("No subdomains found")
	}

	fmt.Println("\n=== DNS Resolution ===")
	resolver := dns.NewResolver()
	records, err := resolver.Lookup("example.com", "A")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		if len(records) > 0 {
			for _, record := range records {
				fmt.Printf("%s: %s\n", record.Type, record.Value)
			}
		} else {
			fmt.Println("No A records found")
		}
	}

	fmt.Println("\n=== SSL/TLS Analysis ===")
	sslTargets := []string{"google.com:443", "github.com:443", "example.com:443"}
	var sslSuccess bool
	for _, target := range sslTargets {
		sslAnalyzer := ssl.NewAnalyzer(target)
		cert, err := sslAnalyzer.Analyze()
		if err != nil {
			continue
		}
		sslSuccess = true
		fmt.Printf("Target: %s\n", target)
		fmt.Printf("Issuer: %s\n", cert.Issuer)
		fmt.Printf("Subject: %s\n", cert.Subject)
		fmt.Printf("Valid: %v\n", cert.IsValid)
		fmt.Printf("Days until expiry: %d\n", cert.DaysUntilExpiry)
		fmt.Printf("TLS Version: %s\n", cert.TLSVersion)
		if len(cert.WeakCiphers) > 0 {
			fmt.Printf("Weak ciphers detected: %v\n", cert.WeakCiphers)
		}
		break
	}
	if !sslSuccess {
		fmt.Println("Could not analyze SSL/TLS (targets may be unreachable or blocking connections)")
	}

	fmt.Println("\n=== Service Fingerprinting ===")
	fp := fingerprint.NewFingerprinter()
	if len(results) > 0 {
		for i, result := range results {
			if i >= 2 {
				break
			}
			fmt.Printf("Testing port %d on localhost...\n", result.Port)
			serviceInfo, err := fp.Fingerprint("127.0.0.1", result.Port)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
			} else {
				fmt.Printf("Service: %s\n", serviceInfo.Service)
				if serviceInfo.Version != "unknown" {
					fmt.Printf("Version: %s\n", serviceInfo.Version)
				}
				if serviceInfo.Banner != "" {
					fmt.Printf("Banner: %s\n", serviceInfo.Banner)
				} else {
					fmt.Println("No banner received (service may require specific protocol handshake)")
				}
				fmt.Printf("Confidence: %d%%\n", serviceInfo.Confidence)
			}
			if i < len(results)-1 {
				fmt.Println()
			}
		}
	} else {
		fmt.Println("No open ports found to fingerprint")
	}

	fmt.Println("\n=== Network Mapping ===")
	fmt.Println("Scanning localhost network (127.0.0.0/24)...")
	netMapper := mapper.NewMapper("127.0.0.0/24")
	hosts := netMapper.Discover()
	if len(hosts) == 0 {
		fmt.Println("No hosts discovered")
		fmt.Println("Note: For real network scanning, use: mapper.NewMapper(\"192.168.1.0/24\")")
		fmt.Println("      Ensure you have permission to scan the target network")
	} else {
		fmt.Printf("Discovered %d hosts:\n", len(hosts))
		for _, host := range hosts {
			fmt.Printf("  %s", host.IP)
			if host.Hostname != "" {
				fmt.Printf(" (%s)", host.Hostname)
			}
			if len(host.Ports) > 0 {
				fmt.Printf(" - Ports: %v", host.Ports)
			}
			fmt.Println()
		}
	}

	fmt.Println("\n=== Packet Capture ===")
	interfaceName := "eth0"
	if runtime.GOOS == "windows" {
		interfaceName = "\\Device\\NPF_{GUID}"
		fmt.Println("Note: On Windows, install Npcap or WinPcap for packet capture")
		fmt.Println("      Use 'getmac /v' to find network interface names")
	}
	packetCapture := capture.NewPacketCapture(interfaceName)
	err = packetCapture.Start()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		fmt.Println("      Packet capture requires administrator privileges and Npcap/WinPcap on Windows")
	} else {
		defer packetCapture.Stop()
		packets := packetCapture.CapturePackets(10)
		fmt.Printf("Captured %d packets\n", len(packets))
		if len(packets) > 0 {
			fmt.Printf("Sample packet: %s -> %s:%d\n", packets[0].SrcIP, packets[0].DstIP, packets[0].DstPort)
		}
	}
}
