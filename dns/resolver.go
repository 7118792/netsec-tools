package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

type DNSRecord struct {
	Type  string
	Value string
	TTL   int
}

type Resolver struct {
	Nameservers []string
	Timeout     time.Duration
}

func NewResolver() *Resolver {
	return &Resolver{
		Nameservers: []string{"8.8.8.8:53", "1.1.1.1:53"},
		Timeout:     5 * time.Second,
	}
}

func (r *Resolver) Lookup(domain string, recordType string) ([]DNSRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
	defer cancel()

	var records []DNSRecord

	switch strings.ToUpper(recordType) {
	case "A":
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			if addr.IP.To4() != nil {
				records = append(records, DNSRecord{
					Type:  "A",
					Value: addr.IP.String(),
				})
			}
		}
	case "AAAA":
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			if addr.IP.To4() == nil {
				records = append(records, DNSRecord{
					Type:  "AAAA",
					Value: addr.IP.String(),
				})
			}
		}
	case "MX":
		mxRecords, err := net.DefaultResolver.LookupMX(ctx, domain)
		if err != nil {
			return nil, err
		}
		for _, mx := range mxRecords {
			records = append(records, DNSRecord{
				Type:  "MX",
				Value: fmt.Sprintf("%s %d", mx.Host, mx.Pref),
			})
		}
	case "TXT":
		txtRecords, err := net.DefaultResolver.LookupTXT(ctx, domain)
		if err != nil {
			return nil, err
		}
		for _, txt := range txtRecords {
			records = append(records, DNSRecord{
				Type:  "TXT",
				Value: txt,
			})
		}
	case "NS":
		nsRecords, err := net.DefaultResolver.LookupNS(ctx, domain)
		if err != nil {
			return nil, err
		}
		for _, ns := range nsRecords {
			records = append(records, DNSRecord{
				Type:  "NS",
				Value: ns.Host,
			})
		}
	case "CNAME":
		cname, err := net.DefaultResolver.LookupCNAME(ctx, domain)
		if err != nil {
			return nil, err
		}
		records = append(records, DNSRecord{
			Type:  "CNAME",
			Value: cname,
		})
	default:
		return nil, fmt.Errorf("unsupported record type: %s", recordType)
	}

	return records, nil
}

func (r *Resolver) ReverseLookup(ip string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil {
		return nil, err
	}

	return names, nil
}

func (r *Resolver) GetAllRecords(domain string) (map[string][]DNSRecord, error) {
	recordTypes := []string{"A", "AAAA", "MX", "TXT", "NS", "CNAME"}
	results := make(map[string][]DNSRecord)

	for _, recordType := range recordTypes {
		records, err := r.Lookup(domain, recordType)
		if err == nil {
			results[recordType] = records
		}
	}

	return results, nil
}
