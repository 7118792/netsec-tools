package mapper

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type Host struct {
	IP       string
	Hostname string
	Ports    []int
	Services map[int]string
}

type NetworkMapper struct {
	Network string
	Hosts   []Host
}

func NewMapper(network string) *NetworkMapper {
	return &NetworkMapper{
		Network: network,
		Hosts:   []Host{},
	}
}

func (nm *NetworkMapper) Discover() []Host {
	ip, ipnet, err := net.ParseCIDR(nm.Network)
	if err != nil {
		return nil
	}

	var wg sync.WaitGroup
	hostsChan := make(chan Host, 256)

	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		wg.Add(1)
		go func(ipAddr net.IP) {
			defer wg.Done()
			if nm.isHostAlive(ipAddr.String()) {
				host := nm.scanHost(ipAddr.String())
				if len(host.Ports) > 0 {
					hostsChan <- host
				}
			}
		}(ip)
	}

	go func() {
		wg.Wait()
		close(hostsChan)
	}()

	var hosts []Host
	for host := range hostsChan {
		hosts = append(hosts, host)
	}

	nm.Hosts = hosts
	return hosts
}

func (nm *NetworkMapper) isHostAlive(ip string) bool {
	conn, err := net.DialTimeout("tcp", ip+":80", 1)
	if err != nil {
		conn, err = net.DialTimeout("tcp", ip+":22", 1)
		if err != nil {
			return false
		}
	}
	conn.Close()
	return true
}

func (nm *NetworkMapper) scanHost(ip string) Host {
	host := Host{
		IP:       ip,
		Services: make(map[int]string),
	}

	commonPorts := []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 5432, 8080}

	for _, port := range commonPorts {
		address := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
		conn, err := net.DialTimeout("tcp", address, 1*time.Second)
		if err == nil {
			host.Ports = append(host.Ports, port)
			conn.Close()
		}
	}

	hostnames, _ := net.LookupAddr(ip)
	if len(hostnames) > 0 {
		host.Hostname = hostnames[0]
	}

	return host
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
