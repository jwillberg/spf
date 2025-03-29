package spf

import (
	"fmt"
	"net"
	"strings"
)

var debugEnabled = false

// EnableDebug enables debug output
func EnableDebug() {
	debugEnabled = true
}

func debugf(format string, args ...interface{}) {
	if debugEnabled {
		fmt.Printf(format+"\n", args...)
	}
}

// SPFEvaluator handles the evaluation of SPF records
type SPFEvaluator struct {
	resolver       *DNSResolver
	includeLookups map[string]bool
	maxDNSLookups  int
	dnsLookups     int
	depth          int // for debug indentation
}

// NewSPFEvaluator creates a new SPF evaluator
func NewSPFEvaluator(resolver *DNSResolver) *SPFEvaluator {
	return &SPFEvaluator{
		resolver:       resolver,
		includeLookups: make(map[string]bool),
		maxDNSLookups:  50,
		dnsLookups:     0,
		depth:          0,
	}
}

// normalizeDomain converts the given domain string to lowercase, trims leading and trailing spaces,
// and removes any trailing dot (e.g., "example.com."). This ensures a canonical form for domain
// comparisons and lookups.
func normalizeDomain(d string) string {
    d = strings.ToLower(strings.TrimSpace(d))
    d = strings.TrimSuffix(d, ".")
    return d
}

// EvaluateSPF evaluates an SPF record for a given IP and domain
func (e *SPFEvaluator) EvaluateSPF(ip net.IP, domain string, record *SPFRecord) (string, error) {
	// Normalize domain before we do anything else
	domain = normalizeDomain(domain)

	debugf("%sChecking SPF for IP %s and domain %s", indent(e.depth), ip.String(), domain)
	debugf("%s↳ SPF: %s", indent(e.depth+1), record.Raw)

	for _, mechanism := range record.Mechanisms {
		matched, err := e.evaluateMechanism(ip, domain, mechanism)
		if err != nil {
			if strings.Contains(err.Error(), "DNS lookup limit exceeded") {
				return ResultPermError, fmt.Errorf("permerror: %v", err)
			}
			return ResultTempError, fmt.Errorf("temperror: %v", err)
		}

		matchedResult := qualifierToResult(mechanism.Qualifier)
		if matched {
			debugf("%s↳ %s → MATCHED (%s)", indent(e.depth+2), mechanismToSimpleString(mechanism), matchedResult)
			return matchedResult, nil
		} else {
			debugf("%s↳ %s → not matched", indent(e.depth+2), mechanismToSimpleString(mechanism))
		}
	}

	if redirectDomain, ok := record.Modifiers["redirect"]; ok && redirectDomain != "" {
	    // Normalize the redirect domain to avoid duplicates like "example.com." vs "example.com"
	    redirectDomain = normalizeDomain(redirectDomain)

	    // Check if we've already processed this domain (circular redirect)
	    if e.includeLookups[redirectDomain] {
	        return ResultPermError, fmt.Errorf("permerror: circular redirect detected: %s", redirectDomain)
    	}
	    // Mark the domain as seen
	    e.includeLookups[redirectDomain] = true

	    debugf("%s↳ redirect=%s", indent(e.depth+2), redirectDomain)

	    // Enforce DNS lookup limit
	    if e.dnsLookups+1 > e.maxDNSLookups {
        	return ResultPermError, fmt.Errorf("permerror: DNS lookup limit exceeded")
	    }
	    e.dnsLookups++

	    // Fetch the SPF record of the redirect domain
	    spfRecord, err := e.resolver.getSPFRecord(redirectDomain)
	    if err != nil {
        	return ResultTempError, fmt.Errorf("temperror: failed to fetch redirect SPF: %v", err)
	    }

	    // Parse the fetched SPF record
	    parsedRecord, err := ParseSPFRecord(spfRecord)
	    if err != nil {
	        return ResultPermError, fmt.Errorf("permerror: failed to parse redirect SPF: %v", err)
	    }

	    // Recursively evaluate the SPF record of the redirected domain
	    e.depth++
	    res, err := e.EvaluateSPF(ip, redirectDomain, parsedRecord)
	    e.depth--

	    debugf("%s↳ Final result: %s", indent(e.depth+2), res)
	    return res, err
	}

	debugf("%s↳ Final result: neutral", indent(e.depth+1))
	return ResultNeutral, nil
}

// evaluateMechanism evaluates a single SPF mechanism
func (e *SPFEvaluator) evaluateMechanism(ip net.IP, domain string, mechanism Mechanism) (bool, error) {
	switch mechanism.Type {
	case MechanismAll:
		return true, nil
	case MechanismIP4:
		if ip.To4() == nil {
			return false, nil
		}
		return mechanism.IPNet.Contains(ip), nil
	case MechanismIP6:
		if ip.To4() != nil {
			return false, nil
		}
		return mechanism.IPNet.Contains(ip), nil
	case MechanismA:
		e.dnsLookups++
		if e.dnsLookups > e.maxDNSLookups {
			return false, fmt.Errorf("DNS lookup limit exceeded")
		}
		targetDomain := domain
		if mechanism.Domain != "" {
			targetDomain = mechanism.Domain
		}
		ips, err := e.resolver.lookupA(targetDomain)
		if err != nil {
			return false, err
		}
		for _, aIP := range ips {
			if mechanism.Prefix != -1 {
				mask := net.CIDRMask(mechanism.Prefix, 32)
				if ip.To4() != nil && aIP.To4() != nil && net.IP.Equal(ip.Mask(mask), aIP.Mask(mask)) {
					return true, nil
				}
			} else if net.IP.Equal(ip, aIP) {
				return true, nil
			}
		}
		return false, nil
	case MechanismMX:
		e.dnsLookups++
		if e.dnsLookups > e.maxDNSLookups {
			return false, fmt.Errorf("DNS lookup limit exceeded")
		}
		targetDomain := domain
		if mechanism.Domain != "" {
			targetDomain = mechanism.Domain
		}
		mxRecords, err := e.resolver.lookupMX(targetDomain)
		if err != nil {
			return false, err
		}
		for _, mx := range mxRecords {
			e.dnsLookups++
			if e.dnsLookups > e.maxDNSLookups {
				return false, fmt.Errorf("DNS lookup limit exceeded")
			}
			ips, err := e.resolver.lookupA(mx.Host)
			if err != nil {
				continue
			}
			for _, mxIP := range ips {
				if mechanism.Prefix != -1 {
					mask := net.CIDRMask(mechanism.Prefix, 32)
					if ip.To4() != nil && mxIP.To4() != nil && net.IP.Equal(ip.Mask(mask), mxIP.Mask(mask)) {
						return true, nil
					}
				} else if net.IP.Equal(ip, mxIP) {
					return true, nil
				}
			}
		}
		return false, nil
	case MechanismInclude:
	    // First, normalize the domain in case it's written differently.
	    includeDomain := normalizeDomain(mechanism.Domain)

	    // Check if we've already included the same domain (circular reference).
	    if e.includeLookups[includeDomain] {
        	// If we've seen this domain before, it's a circular include => permerror.
	        return false, fmt.Errorf("circular include detected: %s", includeDomain)
	    }
	    // Mark this domain as seen to avoid circular references.
	    e.includeLookups[includeDomain] = true

	    // Increment the DNS lookups count to avoid exceeding the limit.
	    e.dnsLookups++
	    if e.dnsLookups > e.maxDNSLookups {
	        return false, fmt.Errorf("DNS lookup limit exceeded")
	    }

	    debugf("%s↳ include:%s", indent(e.depth+1), includeDomain)

	    // Retrieve the SPF record for the included domain.
	    spfRecord, err := e.resolver.getSPFRecord(includeDomain)
	    if err != nil {
        	// If we cannot fetch the record (NXDOMAIN, timeout, etc.),
	        // the 'include' simply does NOT match (false, nil).
        	return false, nil
	    }

	    // If getSPFRecord returns an empty string, there's no SPF for this domain.
	    // The 'include' mechanism therefore does not match, but it's not an error.
	    if spfRecord == "" {
        	return false, nil
	    }

	    // Parse the retrieved SPF record. If parsing fails, decide whether to treat it
	    // as permerror or just "not matched". The spec generally suggests permerror,
	    // but many implementations simply ignore it.
	    parsedRecord, err := ParseSPFRecord(spfRecord)
	    if err != nil {
	        // Return false to indicate this mechanism did not match,
        	// or you can interpret it as permerror.
	        return false, err
    	    }

	    // Re-enter EvaluateSPF to process the included domain's record.
	    e.depth++
	    result, err := e.EvaluateSPF(ip, includeDomain, parsedRecord)
	    e.depth--

	    // For an "include" mechanism, it's only a match if the sub-check result is "pass".
	    return result == ResultPass, err
	case MechanismExists:
		e.dnsLookups++
		if e.dnsLookups > e.maxDNSLookups {
			return false, fmt.Errorf("DNS lookup limit exceeded")
		}
		ips, err := e.resolver.lookupA(mechanism.Domain)
		if err != nil {
			return false, nil
		}
		return len(ips) > 0, nil
	case MechanismPTR:
		e.dnsLookups++
		if e.dnsLookups > e.maxDNSLookups {
			return false, fmt.Errorf("DNS lookup limit exceeded")
		}
		return false, nil
	default:
		return false, fmt.Errorf("unknown mechanism type: %s", mechanism.Type)
	}
}

func mechanismToString(m Mechanism) string {
	prefix := string(m.Qualifier)
	switch m.Type {
	case MechanismInclude:
		return fmt.Sprintf("%sinclude:%s", prefix, m.Domain)
	case MechanismA:
		if m.Domain != "" {
			return fmt.Sprintf("%sa:%s", prefix, m.Domain)
		}
		return fmt.Sprintf("%sa", prefix)
	case MechanismMX:
		if m.Domain != "" {
			return fmt.Sprintf("%smx:%s", prefix, m.Domain)
		}
		return fmt.Sprintf("%smx", prefix)
	case MechanismIP4:
		return fmt.Sprintf("%sip4:%s", prefix, m.IPNet.String())
	case MechanismIP6:
		return fmt.Sprintf("%sip6:%s", prefix, m.IPNet.String())
	default:
		return fmt.Sprintf("%s%s", prefix, m.Type)
	}
}

func indent(n int) string {
	return strings.Repeat("  ", n)
}

func mechanismToSimpleString(m Mechanism) string {
	switch m.Type {
	case MechanismInclude:
		return fmt.Sprintf("include:%s", m.Domain)
	case MechanismA:
		if m.Domain != "" {
			return fmt.Sprintf("a:%s", m.Domain)
		}
		return "a"
	case MechanismMX:
		if m.Domain != "" {
			return fmt.Sprintf("mx:%s", m.Domain)
		}
		return "mx"
	case MechanismIP4:
		return fmt.Sprintf("ip4:%s", m.IPNet.String())
	case MechanismIP6:
		return fmt.Sprintf("ip6:%s", m.IPNet.String())
	default:
		return string(m.Type)
	}
}

func qualifierToResult(q Qualifier) string {
	switch q {
	case QualifierPass:
		return "pass"
	case QualifierFail:
		return "fail"
	case QualifierSoftFail:
		return "softfail"
	case QualifierNeutral:
		return "neutral"
	default:
		return "unknown"
	}
}

