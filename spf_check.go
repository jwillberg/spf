package spf

import (
	"fmt"
	"net"
	"strings"
)

// SPFCheck validates if an IP address is authorized to send emails from a specific domain
// Returns one of the following results as defined in RFC 7208 section 2.6:
// - "none": No SPF records found or no valid domain
// - "neutral": Domain explicitly states no assertion
// - "pass": IP is authorized to send mail from this domain
// - "fail": IP is not authorized to send mail from this domain
// - "softfail": IP is probably not authorized (weak policy)
// - "temperror": Temporary error (DNS issues, etc.)
// - "permerror": Permanent error (invalid SPF record, etc.)
func SPFCheck(ip string, domain string, memcacheAddr string) (string, error) {
	// Validate IP address
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return ResultPermError, fmt.Errorf("invalid IP address: %s", ip)
	}

	// Validate domain
	if domain == "" {
		return ResultNone, fmt.Errorf("empty domain")
	}

	// Remove any trailing dots from domain
	domain = strings.TrimSuffix(domain, ".")

	// Create DNS resolver with default servers
	resolver := NewDNSResolver(spfDNSServers, memcacheAddr)

	// Get SPF record for the domain
	spfRecord, err := resolver.getSPFRecord(domain)
	if err != nil {
		// If no SPF record is found, return "none"
		if strings.Contains(err.Error(), "no SPF record found") {
			return ResultNone, nil
		}
		// For other DNS errors, return "temperror"
		return ResultTempError, err
	}

	// If getSPFRecord returned an empty string, that also means "no record" (could be NXDOMAIN).
    	//    => Return "none" to indicate there's no valid SPF.
    	if spfRecord == "" {
        	return ResultNone, nil
    	}

	// Parse the SPF record
	parsedRecord, err := ParseSPFRecord(spfRecord)
	if err != nil {
		return ResultPermError, fmt.Errorf("failed to parse SPF record: %v", err)
	}

	// Create an evaluator and evaluate the SPF record
	evaluator := NewSPFEvaluator(resolver)
	result, err := evaluator.EvaluateSPF(parsedIP, domain, parsedRecord)
	if err != nil {
		// The error message already contains the result type (temperror or permerror)
		return result, err
	}

	return result, nil
}
