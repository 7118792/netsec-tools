package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

type PortResult struct {
	Port     int
	State    string
	Service  string
	Banner   string
	Protocol string
}

type PortScanner struct {
	Target    string
	StartPort int
	EndPort   int
	Threads   int
	Timeout   time.Duration
	Protocol  string
}

func NewPortScanner(target string, startPort, endPort, threads int) *PortScanner {
	return &PortScanner{
		Target:    target,
		StartPort: startPort,
		EndPort:   endPort,
		Threads:   threads,
		Timeout:   3 * time.Second,
		Protocol:  "tcp",
	}
}

func (ps *PortScanner) Scan() []PortResult {
	var results []PortResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	ports := make(chan int, ps.Threads)

	for i := 0; i < ps.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range ports {
				result := ps.scanPort(port)
				if result.State == "open" {
					mu.Lock()
					results = append(results, result)
					mu.Unlock()
				}
			}
		}()
	}

	go func() {
		for port := ps.StartPort; port <= ps.EndPort; port++ {
			ports <- port
		}
		close(ports)
	}()

	wg.Wait()
	return results
}

func (ps *PortScanner) scanPort(port int) PortResult {
	result := PortResult{
		Port:     port,
		State:    "closed",
		Protocol: ps.Protocol,
	}

	address := fmt.Sprintf("%s:%d", ps.Target, port)
	ctx, cancel := context.WithTimeout(context.Background(), ps.Timeout)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, ps.Protocol, address)
	if err != nil {
		return result
	}
	defer conn.Close()

	result.State = "open"
	result.Service = ps.detectService(port)
	result.Banner = ps.grabBanner(conn)

	return result
}

func (ps *PortScanner) detectService(port int) string {
	services := map[int]string{
		21:   "ftp",
		22:   "ssh",
		23:   "telnet",
		25:   "smtp",
		53:   "dns",
		80:   "http",
		110:  "pop3",
		143:  "imap",
		443:  "https",
		3306: "mysql",
		5432: "postgresql",
		8080: "http-proxy",
	}

	if service, ok := services[port]; ok {
		return service
	}
	return "unknown"
}

func (ps *PortScanner) grabBanner(conn net.Conn) string {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}
	return string(buffer[:n])
}

func (ps *PortScanner) ScanUDP() []PortResult {
	ps.Protocol = "udp"
	return ps.Scan()
}
