package spf

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/bradfitz/gomemcache/memcache"
)

// SPF DNS servers to use for lookups
var spfDNSServers = []string{"8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"}

// ErrNXDOMAIN is used to indicate that the domain does not exist (NXDOMAIN).
var ErrNXDOMAIN = errors.New("nxdomain")
var errNoSPF = errors.New("no SPF record found") // <- tämä tänne!

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

	// Optional Memcache client. If nil, no caching is used.
	mc *memcache.Client
}

// NewDNSResolver creates a new DNS resolver with the specified servers
// If memcacheAddr is an empty string, no memcache usage
func NewDNSResolver(servers []string, memcacheAddr string) *DNSResolver {
	if len(servers) == 0 {
		servers = spfDNSServers
	}
	res := &DNSResolver{
		servers: servers,
		client:  &dns.Client{},
	}

	// If memcacheAddr is not empty, create a memcache.Client
	if memcacheAddr != "" {
		res.mc = memcache.New(memcacheAddr) // e.g. "127.0.0.1:11211"
	}

	return res
}

// lookupTXT performs a TXT record lookup for a domain
func (r *DNSResolver) lookupTXT(domain string) ([]string, error) {
    // 1) If memcache is available, check if we have a cached value
    if r.mc != nil {
        cacheKey := "spf_txt_" + domain
        if item, err := r.mc.Get(cacheKey); err == nil {
            // We have a cached entry. Convert item.Value (e.g. CSV -> slice)
            cachedStr := string(item.Value)
            // Suppose we stored them joined by "|"
            txtRecords := strings.Split(cachedStr, "|")
            return txtRecords, nil
        }
    }

    var txtRecords []string
    var lastErr error

    // Use a custom dns.Client so we can manually handle UDP and TCP fallback
    c := &dns.Client{Timeout: 5 * time.Second}
    // Alternatively, you could set c.Net = "udp" here, but we manage fallback below

    // Try each DNS server in turn
    for _, server := range r.servers {
	//debugf("Trying DNS server: %s", server)

        serverAddr := net.JoinHostPort(server, "53")

        // Build the query, enabling EDNS with a larger payload size
        m := new(dns.Msg)
        m.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)
        m.RecursionDesired = true

        // Enable EDNS0 to handle larger responses in UDP
        // (e.g., up to 4096 bytes – adjust as needed)
        m.SetEdns0(4096, true)

        // First, do a UDP query
        resp, _, err := c.Exchange(m, serverAddr)
        if err != nil {
            lastErr = err
            continue
        }

        // If the response is truncated, retry over TCP
        if resp.Truncated {
            cTCP := &dns.Client{Net: "tcp"}
            resp, _, err = cTCP.Exchange(m, serverAddr)
            if err != nil {
                lastErr = err
                continue
            }
        }

        // If the response code is NXDOMAIN (NameError), assign ErrNXDOMAIN and continue.
        if resp.Rcode == dns.RcodeNameError {
            lastErr = ErrNXDOMAIN
            continue
        } else if resp.Rcode != dns.RcodeSuccess {
            // For other non-success codes, set a generic error and continue to the next server.
            lastErr = fmt.Errorf("DNS lookup failed with code: %d", resp.Rcode)
            continue
        }

        // Parse the TXT answers
        var foundAny bool
        var storeTTL uint32 = 300 // default fallback if no answer

        for _, ans := range resp.Answer {
            if txt, ok := ans.(*dns.TXT); ok {
                // Take the TTL from the first matching answer
                storeTTL = ans.Header().Ttl

                // Join all TXT chunks — mail.ru often returns multiple chunks
                record := strings.Join(txt.Txt, "")

		// 🧼 Clean string
		record = strings.TrimSpace(record)
		record = strings.Trim(record, "\"")
		record = strings.TrimPrefix(record, "\\\"")
		record = strings.TrimSuffix(record, "\\\"")

                // If “v=spf1” is missing a space after the version, insert it
                if strings.HasPrefix(record, "v=spf1") && len(record) > 6 && record[6] != ' ' {
                    record = "v=spf1 " + record[6:]
                }
                txtRecords = append(txtRecords, record)
                foundAny = true
            }
        }

        // As soon as we find at least one TXT record, return
        if foundAny {
            // If memcache is available, store
            if r.mc != nil {
                cacheKey := "spf_txt_" + domain
                // Join records with "|"
                joined := strings.Join(txtRecords, "|")

                // storeTTL is in seconds
                // If storeTTL is very large, memcache supports up to ~30 days in seconds
                // If bigger, must be a Unix timestamp, but let's assume it's small
                item := &memcache.Item{
                    Key:        cacheKey,
                    Value:      []byte(joined),
                    Expiration: int32(storeTTL),
                }
                _ = r.mc.Set(item) // ignore set error
            }

            return txtRecords, nil
        }

        // Valid NOERROR response, but no TXT records — treat as empty, not error
        if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0 {
            return []string{}, nil
        }
    }

    if lastErr == nil {
        return []string{}, nil
    }

    if errors.Is(lastErr, ErrNXDOMAIN) {
        return nil, ErrNXDOMAIN
    }

    return nil, fmt.Errorf("all DNS servers failed: %w", lastErr)
}

// lookupA performs an A record lookup for a domain
func (r *DNSResolver) lookupA(domain string) ([]net.IP, error) {
    	// 1) If memcache is available, check if we have a cached value
	if r.mc != nil {
            cacheKey := "spf_a_" + domain
            if item, err := r.mc.Get(cacheKey); err == nil {
                // Convert the cached string -> slice of IP addresses
                // Suppose we stored them comma-separated
                cachedStr := string(item.Value)
                if cachedStr == "" {
                    // Means we had no IP addresses previously
                    return []net.IP{}, nil
                }
                ipStrs := strings.Split(cachedStr, ",")
                var ips []net.IP
                for _, s := range ipStrs {
                    ips = append(ips, net.ParseIP(s))
                }
                return ips, nil
            }
        }

	var ipAddresses []net.IP
	var lastErr error

	for _, server := range r.servers {
		debugf("Trying DNS server: %s", server)

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

                // We can store the minimal TTL from the A answers
                var storeTTL uint32 = 300 // fallback

		for _, ans := range resp.Answer {
			if a, ok := ans.(*dns.A); ok {
				ipAddresses = append(ipAddresses, a.A)
           			if ans.Header().Ttl < storeTTL {
		                    storeTTL = ans.Header().Ttl
                		}
			}
		}

		if len(ipAddresses) > 0 {
	            // Cache these IP addresses
        	    if r.mc != nil {
	                cacheKey := "spf_a_" + domain

        	        // Combine addresses into a comma-separated string
	                var ipStrs []string
        	        for _, ip := range ipAddresses {
                	    ipStrs = append(ipStrs, ip.String())
	                }
        	        joined := strings.Join(ipStrs, ",")

	                item := &memcache.Item{
        	            Key:        cacheKey,
                	    Value:      []byte(joined),
	                    Expiration: int32(storeTTL),
        	        }
                	_ = r.mc.Set(item)
	            }
		    return ipAddresses, nil
		}
	}

    if lastErr == nil {
        return []net.IP{}, nil
    }

    if errors.Is(lastErr, ErrNXDOMAIN) {
        return nil, ErrNXDOMAIN
    }

    return nil, fmt.Errorf("all DNS servers failed: %w", lastErr)
}

// lookupMX performs an MX record lookup for a domain
func (r *DNSResolver) lookupMX(domain string) ([]*net.MX, error) {
    	// 1) If memcache is available, check if we have a cached value
	if r.mc != nil {
            cacheKey := "spf_mx_" + domain
	    if item, err := r.mc.Get(cacheKey); err == nil {
        	// Convert the cached string -> slice of net.MX
	        // Suppose we stored each MX as "pref:host" separated by "|"
        	cachedStr := string(item.Value)
	        if cachedStr == "" {
        	    return []*net.MX{}, nil
	        }
        	parts := strings.Split(cachedStr, "|")
	        var mxs []*net.MX
        	for _, p := range parts {
	            // e.g. "10:mail.google.com"
        	    sub := strings.SplitN(p, ":", 2)
	            if len(sub) == 2 {
        	        // parse preference
                        // sub[0] => preference, sub[1] => host
	                // Example: sub[0] = "10", sub[1] = "mail.google.com"
        	        var pref uint16 = 0
	                fmt.Sscanf(sub[0], "%d", &pref)
        	        mxs = append(mxs, &net.MX{
                	        Host: sub[1],
	                        Pref: pref,
        	        })
	            }
        	 }
	         return mxs, nil
             }
    	}

	var mxRecords []*net.MX
	var lastErr error

	for _, server := range r.servers {
		debugf("Trying DNS server: %s", server)

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

		// We'll determine TTL from the first MX record or pick a min
	        var storeTTL uint32 = 300
		for _, ans := range resp.Answer {
			if mx, ok := ans.(*dns.MX); ok {
				mxRecords = append(mxRecords, &net.MX{
					Host: mx.Mx,
					Pref: mx.Preference,
				})
				if ans.Header().Ttl < storeTTL {
		                    storeTTL = ans.Header().Ttl
                		}
			}
		}

		if len(mxRecords) > 0 {
	            	// Cache the MX records
  	                if r.mc != nil {
		                cacheKey := "spf_mx_" + domain
	
        		        // Each record as "pref:host", joined by "|"
		                var parts []string
                		for _, rec := range mxRecords {
		                    parts = append(parts, fmt.Sprintf("%d:%s", rec.Pref, rec.Host))
                		}
		                joined := strings.Join(parts, "|")

                		item := &memcache.Item{
		                    Key:        cacheKey,
                		    Value:      []byte(joined),
		                    Expiration: int32(storeTTL),
                		}
		                _ = r.mc.Set(item)
            		}
			return mxRecords, nil
		}
	}

	if len(mxRecords) > 0 {
	    return mxRecords, nil
	}

	// No MX records found
	if lastErr == nil {
	    // Domain exists (e.g. SOA returned), but no MX records found – that's valid.
	    return []*net.MX{}, nil
	}

	if errors.Is(lastErr, ErrNXDOMAIN) {
	    return nil, ErrNXDOMAIN
	}

	// Other error (timeout, SERVFAIL, etc.)
	return nil, fmt.Errorf("all DNS servers failed: %w", lastErr)
}


// getSPFRecord retrieves the SPF record for a domain
func (r *DNSResolver) getSPFRecord(domain string) (string, error) {
    // Fetch all TXT records for this domain.
    txtRecords, err := r.lookupTXT(domain)
    if err != nil {
        // If the error is specifically NXDOMAIN, we treat it as "no domain => no SPF".
        if errors.Is(err, ErrNXDOMAIN) {
            // Return empty string and no error, so that upper layers interpret it as "none".
            return "", nil
        }
        // Otherwise, return the encountered error.
        return "", err
    }

    // Iterate through the TXT records and look for one that starts with "v=spf1".
    for _, record := range txtRecords {
        if strings.HasPrefix(record, "v=spf1 ") || record == "v=spf1" {
            // Found a valid SPF record.
            return record, nil
        }
    }

    // If no SPF string was found in the TXT records, return a "no SPF found" error.
    return "", errNoSPF
}
