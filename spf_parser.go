package spf

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// SPFRecord represents a parsed SPF record
type SPFRecord struct {
	Raw        string
	Mechanisms []Mechanism
	Modifiers  map[string]string
}

// MechanismType represents the type of SPF mechanism
type MechanismType string

const (
	MechanismAll     MechanismType = "all"
	MechanismIP4     MechanismType = "ip4"
	MechanismIP6     MechanismType = "ip6"
	MechanismA       MechanismType = "a"
	MechanismMX      MechanismType = "mx"
	MechanismPTR     MechanismType = "ptr"
	MechanismExists  MechanismType = "exists"
	MechanismInclude MechanismType = "include"
)

// Qualifier represents the qualifier for an SPF mechanism
type Qualifier string

const (
	QualifierPass    Qualifier = "+"
	QualifierFail    Qualifier = "-"
	QualifierSoftFail Qualifier = "~"
	QualifierNeutral Qualifier = "?"
)

// Mechanism represents an SPF mechanism with its qualifier and parameters
type Mechanism struct {
	Type      MechanismType
	Qualifier Qualifier
	Domain    string
	IP        net.IP
	IPNet     *net.IPNet
	Prefix    int
}

// ParseSPFRecord parses an SPF record string into an SPFRecord struct
func ParseSPFRecord(record string) (*SPFRecord, error) {
	if record == "" {
		return nil, fmt.Errorf("empty SPF record")
	}

	// Check if the record starts with "v=spf1"
	if !strings.HasPrefix(record, "v=spf1") {
		return nil, fmt.Errorf("invalid SPF record: does not start with v=spf1")
	}

	// Split the record into terms
	terms := strings.Fields(record)
	if len(terms) < 1 {
		return nil, fmt.Errorf("invalid SPF record: no terms found")
	}

	// Skip the version term
	terms = terms[1:]

	spfRecord := &SPFRecord{
		Raw:        record,
		Mechanisms: []Mechanism{},
		Modifiers:  make(map[string]string),
	}

	// Parse each term
	for _, term := range terms {
		if strings.Contains(term, "=") {
			// This is a modifier
			parts := strings.SplitN(term, "=", 2)
			if len(parts) == 2 {
				spfRecord.Modifiers[parts[0]] = parts[1]
			}
		} else {
			// This is a mechanism
			mechanism, err := parseMechanism(term)
			if err != nil {
				return nil, err
			}
			spfRecord.Mechanisms = append(spfRecord.Mechanisms, *mechanism)
		}
	}

	return spfRecord, nil
}

// parseMechanism parses a mechanism string into a Mechanism struct
func parseMechanism(term string) (*Mechanism, error) {
	mechanism := &Mechanism{
		Qualifier: QualifierPass, // Default qualifier is "+" (pass)
		Prefix:    -1,            // Default prefix is unspecified
	}

	// Check for qualifier
	if strings.HasPrefix(term, "+") || strings.HasPrefix(term, "-") ||
		strings.HasPrefix(term, "~") || strings.HasPrefix(term, "?") {
		mechanism.Qualifier = Qualifier(term[0:1])
		term = term[1:]
	}

	// Parse mechanism type and parameters
	if strings.HasPrefix(term, "all") {
		mechanism.Type = MechanismAll
	} else if strings.HasPrefix(term, "include:") {
		mechanism.Type = MechanismInclude
		mechanism.Domain = term[8:]
	} else if strings.HasPrefix(term, "a") {
		mechanism.Type = MechanismA
		// Check if there's a domain specified
		if strings.HasPrefix(term, "a:") {
			domainAndPrefix := term[2:]
			mechanism.Domain, mechanism.Prefix = parseDomainAndPrefix(domainAndPrefix)
		}
	} else if strings.HasPrefix(term, "mx") {
		mechanism.Type = MechanismMX
		// Check if there's a domain specified
		if strings.HasPrefix(term, "mx:") {
			domainAndPrefix := term[3:]
			mechanism.Domain, mechanism.Prefix = parseDomainAndPrefix(domainAndPrefix)
		}
	} else if strings.HasPrefix(term, "ptr") {
		mechanism.Type = MechanismPTR
		// Check if there's a domain specified
		if strings.HasPrefix(term, "ptr:") {
			mechanism.Domain = term[4:]
		}
	} else if strings.HasPrefix(term, "ip4:") {
		mechanism.Type = MechanismIP4
		ipAndPrefix := term[4:]
		ip, ipNet, prefix, err := parseIP4AndPrefix(ipAndPrefix)
		if err != nil {
			return nil, err
		}
		mechanism.IP = ip
		mechanism.IPNet = ipNet
		mechanism.Prefix = prefix
	} else if strings.HasPrefix(term, "ip6:") {
		mechanism.Type = MechanismIP6
		ipAndPrefix := term[4:]
		ip, ipNet, prefix, err := parseIP6AndPrefix(ipAndPrefix)
		if err != nil {
			return nil, err
		}
		mechanism.IP = ip
		mechanism.IPNet = ipNet
		mechanism.Prefix = prefix
	} else if strings.HasPrefix(term, "exists:") {
		mechanism.Type = MechanismExists
		mechanism.Domain = term[7:]
	} else {
		return nil, fmt.Errorf("unknown mechanism: %s", term)
	}

	return mechanism, nil
}

// parseDomainAndPrefix parses a domain with an optional CIDR prefix
func parseDomainAndPrefix(s string) (string, int) {
	parts := strings.Split(s, "/")
	domain := parts[0]
	prefix := -1

	if len(parts) > 1 {
		var err error
		prefix, err = strconv.Atoi(parts[1])
		if err != nil {
			prefix = -1
		}
	}

	return domain, prefix
}

// parseIP4AndPrefix parses an IPv4 address with an optional CIDR prefix
func parseIP4AndPrefix(s string) (net.IP, *net.IPNet, int, error) {
	parts := strings.Split(s, "/")
	ipStr := parts[0]
	prefix := 32 // Default prefix for IPv4

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, nil, 0, fmt.Errorf("invalid IPv4 address: %s", ipStr)
	}

	// Convert to IPv4 format if it's in IPv6-mapped IPv4 format
	if ip.To4() != nil {
		ip = ip.To4()
	}

	if len(parts) > 1 {
		var err error
		prefix, err = strconv.Atoi(parts[1])
		if err != nil {
			return nil, nil, 0, fmt.Errorf("invalid prefix: %s", parts[1])
		}
		if prefix < 0 || prefix > 32 {
			return nil, nil, 0, fmt.Errorf("IPv4 prefix must be between 0 and 32")
		}
	}

	// Create the IPNet
	mask := net.CIDRMask(prefix, 32)
	ipNet := &net.IPNet{
		IP:   ip.Mask(mask),
		Mask: mask,
	}

	return ip, ipNet, prefix, nil
}

// parseIP6AndPrefix parses an IPv6 address with an optional CIDR prefix
func parseIP6AndPrefix(s string) (net.IP, *net.IPNet, int, error) {
	parts := strings.Split(s, "/")
	ipStr := parts[0]
	prefix := 128 // Default prefix for IPv6

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, nil, 0, fmt.Errorf("invalid IPv6 address: %s", ipStr)
	}

	if len(parts) > 1 {
		var err error
		prefix, err = strconv.Atoi(parts[1])
		if err != nil {
			return nil, nil, 0, fmt.Errorf("invalid prefix: %s", parts[1])
		}
		if prefix < 0 || prefix > 128 {
			return nil, nil, 0, fmt.Errorf("IPv6 prefix must be between 0 and 128")
		}
	}

	// Create the IPNet
	mask := net.CIDRMask(prefix, 128)
	ipNet := &net.IPNet{
		IP:   ip.Mask(mask),
		Mask: mask,
	}

	return ip, ipNet, prefix, nil
}
