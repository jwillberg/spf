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
		maxDNSLookups:  10,
		dnsLookups:     0,
		depth:          0,
	}
}

// EvaluateSPF evaluates an SPF record for a given IP and domain
func (e *SPFEvaluator) EvaluateSPF(ip net.IP, domain string, record *SPFRecord) (string, error) {
	e.includeLookups = make(map[string]bool)
	e.dnsLookups = 0

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
		debugf("%s↳ redirect=%s", indent(e.depth+2), redirectDomain)
		if e.dnsLookups+1 > e.maxDNSLookups {
			return ResultPermError, fmt.Errorf("permerror: DNS lookup limit exceeded")
		}
		e.dnsLookups++
		spfRecord, err := e.resolver.getSPFRecord(redirectDomain)
		if err != nil {
			return ResultTempError, fmt.Errorf("temperror: failed to fetch redirect SPF: %v", err)
		}
		parsedRecord, err := ParseSPFRecord(spfRecord)
		if err != nil {
			return ResultPermError, fmt.Errorf("permerror: failed to parse redirect SPF: %v", err)
		}
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
		if e.includeLookups[mechanism.Domain] {
			return false, fmt.Errorf("circular include detected: %s", mechanism.Domain)
		}
		e.includeLookups[mechanism.Domain] = true
		e.dnsLookups++
		if e.dnsLookups > e.maxDNSLookups {
			return false, fmt.Errorf("DNS lookup limit exceeded")
		}
		debugf("%s↳ include:%s", indent(e.depth+1), mechanism.Domain)
		spfRecord, err := e.resolver.getSPFRecord(mechanism.Domain)
		if err != nil {
			return false, nil
		}
		parsedRecord, err := ParseSPFRecord(spfRecord)
		if err != nil {
			return false, err
		}
		e.depth++
		result, err := e.EvaluateSPF(ip, mechanism.Domain, parsedRecord)
		e.depth--
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

