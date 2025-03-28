package spf

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// SPF DNS servers to use for lookups
var spfDNSServers = []string{"8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"}

// SPF result types as defined in RFC 7208
const (
	ResultNone      = "none"      // No SPF records found or no valid domain
	ResultNeutral   = "neutral"   // Domain explicitly states no assertion (?)
	ResultPass      = "pass"      // IP is authorized to send mail from this domain
	ResultFail      = "fail"      // IP is not authorized to send mail from this domain
	ResultSoftFail  = "softfail"  // IP is probably not authorized (weak policy)
	ResultTempError = "temperror" // Temporary error (DNS issues, etc.)
	ResultPermError = "permerror" // Permanent error (invalid SPF record, etc.)
)

// DNSResolver handles DNS lookups for SPF validation
type DNSResolver struct {
	servers []string
	client  *dns.Client
}

// NewDNSResolver creates a new DNS resolver with the specified servers
func NewDNSResolver(servers []string) *DNSResolver {
	if len(servers) == 0 {
		servers = spfDNSServers
	}
	return &DNSResolver{
		servers: servers,
		client:  &dns.Client{},
	}
}

// lookupTXT performs a TXT record lookup for a domain
func (r *DNSResolver) lookupTXT(domain string) ([]string, error) {
	var txtRecords []string
	var lastErr error

	// Try each DNS server until we get a response
	for _, server := range r.servers {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)
		m.RecursionDesired = true

		serverAddr := net.JoinHostPort(server, "53")
		resp, _, err := r.client.Exchange(m, serverAddr)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("DNS lookup failed with code: %d", resp.Rcode)
			continue
		}

		for _, ans := range resp.Answer {
			if txt, ok := ans.(*dns.TXT); ok {
				txtRecords = append(txtRecords, strings.Join(txt.Txt, ""))
			}
		}

		if len(txtRecords) > 0 {
			return txtRecords, nil
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return txtRecords, nil
}

// lookupA performs an A record lookup for a domain
func (r *DNSResolver) lookupA(domain string) ([]net.IP, error) {
	var ipAddresses []net.IP
	var lastErr error

	for _, server := range r.servers {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
		m.RecursionDesired = true

		serverAddr := net.JoinHostPort(server, "53")
		resp, _, err := r.client.Exchange(m, serverAddr)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("DNS lookup failed with code: %d", resp.Rcode)
			continue
		}

		for _, ans := range resp.Answer {
			if a, ok := ans.(*dns.A); ok {
				ipAddresses = append(ipAddresses, a.A)
			}
		}

		if len(ipAddresses) > 0 {
			return ipAddresses, nil
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return ipAddresses, nil
}

// lookupMX performs an MX record lookup for a domain
func (r *DNSResolver) lookupMX(domain string) ([]*net.MX, error) {
	var mxRecords []*net.MX
	var lastErr error

	for _, server := range r.servers {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(domain), dns.TypeMX)
		m.RecursionDesired = true

		serverAddr := net.JoinHostPort(server, "53")
		resp, _, err := r.client.Exchange(m, serverAddr)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("DNS lookup failed with code: %d", resp.Rcode)
			continue
		}

		for _, ans := range resp.Answer {
			if mx, ok := ans.(*dns.MX); ok {
				mxRecords = append(mxRecords, &net.MX{
					Host: mx.Mx,
					Pref: mx.Preference,
				})
			}
		}

		if len(mxRecords) > 0 {
			return mxRecords, nil
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return mxRecords, nil
}

// getSPFRecord retrieves the SPF record for a domain
func (r *DNSResolver) getSPFRecord(domain string) (string, error) {
	txtRecords, err := r.lookupTXT(domain)
	if err != nil {
		return "", err
	}

	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=spf1 ") || record == "v=spf1" {
			return record, nil
		}
	}

	return "", errors.New("no SPF record found")
}
