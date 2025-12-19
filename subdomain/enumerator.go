package subdomain

import (
	"context"
	"net"
	"sync"
	"time"
)

type Enumerator struct {
	Domain      string
	Wordlist    []string
	Concurrency int
	Timeout     time.Duration
}

func NewEnumerator(domain string) *Enumerator {
	return &Enumerator{
		Domain:      domain,
		Concurrency: 50,
		Timeout:     3 * time.Second,
		Wordlist:    getDefaultWordlist(),
	}
}

func (e *Enumerator) Enumerate() []string {
	var found []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	subdomains := make(chan string, e.Concurrency)

	for i := 0; i < e.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for subdomain := range subdomains {
				if e.checkSubdomain(subdomain) {
					mu.Lock()
					found = append(found, subdomain)
					mu.Unlock()
				}
			}
		}()
	}

	go func() {
		for _, word := range e.Wordlist {
			subdomains <- word + "." + e.Domain
		}
		close(subdomains)
	}()

	wg.Wait()
	return found
}

func (e *Enumerator) checkSubdomain(subdomain string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), e.Timeout)
	defer cancel()

	resolver := net.Resolver{}
	_, err := resolver.LookupHost(ctx, subdomain)
	return err == nil
}

func (e *Enumerator) BruteForce(charset string, length int) []string {
	var found []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	combinations := generateCombinations(charset, length)
	subdomains := make(chan string, e.Concurrency)

	for i := 0; i < e.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for subdomain := range subdomains {
				fullDomain := subdomain + "." + e.Domain
				if e.checkSubdomain(fullDomain) {
					mu.Lock()
					found = append(found, fullDomain)
					mu.Unlock()
				}
			}
		}()
	}

	go func() {
		for _, combo := range combinations {
			subdomains <- combo
		}
		close(subdomains)
	}()

	wg.Wait()
	return found
}

func (e *Enumerator) DNSZoneTransfer() []string {
	var records []string

	nameservers := []string{
		"8.8.8.8",
		"1.1.1.1",
	}

	for _, ns := range nameservers {
		conn, err := net.Dial("tcp", ns+":53")
		if err != nil {
			continue
		}
		defer conn.Close()
	}

	return records
}

func getDefaultWordlist() []string {
	return []string{
		"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
		"ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
		"ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
		"mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
		"docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki",
		"web", "media", "email", "images", "img", "www1", "intranet", "portal",
		"video", "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4", "www3", "dns",
		"search", "staging", "server", "mx1", "chat", "wap", "my", "svn", "mail1",
		"sites", "proxy", "ads", "online", "ads", "gw", "app", "1", "2", "3", "4",
		"5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17",
		"18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30",
	}
}

func generateCombinations(charset string, length int) []string {
	if length == 0 {
		return []string{""}
	}

	var result []string
	for _, char := range charset {
		for _, combo := range generateCombinations(charset, length-1) {
			result = append(result, string(char)+combo)
		}
	}
	return result
}
