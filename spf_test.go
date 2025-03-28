package spf

import (
	"net"
	"testing"
)

func TestParseSPFRecord(t *testing.T) {
	tests := []struct {
		name    string
		record  string
		wantErr bool
	}{
		{
			name:    "Valid SPF record with all mechanisms",
			record:  "v=spf1 ip4:192.168.0.1/24 ip6:2001:db8::/32 a mx a:example.com mx:example.com/24 include:example.net -all",
			wantErr: false,
		},
		{
			name:    "Valid SPF record with qualifiers",
			record:  "v=spf1 +ip4:192.168.0.1 ~ip4:192.168.1.1 -ip4:192.168.2.1 ?ip4:192.168.3.1 -all",
			wantErr: false,
		},
		{
			name:    "Invalid SPF record - missing v=spf1",
			record:  "ip4:192.168.0.1 -all",
			wantErr: true,
		},
		{
			name:    "Empty SPF record",
			record:  "",
			wantErr: true,
		},
		{
			name:    "SPF record with modifiers",
			record:  "v=spf1 redirect=example.com exp=explain.example.com -all",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseSPFRecord(tt.record)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSPFRecord() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMechanismParsing(t *testing.T) {
	tests := []struct {
		name     string
		term     string
		wantType MechanismType
		wantQual Qualifier
	}{
		{
			name:     "all mechanism with default qualifier",
			term:     "all",
			wantType: MechanismAll,
			wantQual: QualifierPass,
		},
		{
			name:     "all mechanism with fail qualifier",
			term:     "-all",
			wantType: MechanismAll,
			wantQual: QualifierFail,
		},
		{
			name:     "ip4 mechanism",
			term:     "ip4:192.168.0.1/24",
			wantType: MechanismIP4,
			wantQual: QualifierPass,
		},
		{
			name:     "ip6 mechanism with softfail qualifier",
			term:     "~ip6:2001:db8::/32",
			wantType: MechanismIP6,
			wantQual: QualifierSoftFail,
		},
		{
			name:     "a mechanism with domain",
			term:     "a:example.com",
			wantType: MechanismA,
			wantQual: QualifierPass,
		},
		{
			name:     "mx mechanism with neutral qualifier",
			term:     "?mx:example.com/24",
			wantType: MechanismMX,
			wantQual: QualifierNeutral,
		},
		{
			name:     "include mechanism",
			term:     "include:example.net",
			wantType: MechanismInclude,
			wantQual: QualifierPass,
		},
		{
			name:     "exists mechanism",
			term:     "exists:example.com",
			wantType: MechanismExists,
			wantQual: QualifierPass,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mechanism, err := parseMechanism(tt.term)
			if err != nil {
				t.Fatalf("parseMechanism() error = %v", err)
			}
			if mechanism.Type != tt.wantType {
				t.Errorf("parseMechanism() type = %v, want %v", mechanism.Type, tt.wantType)
			}
			if mechanism.Qualifier != tt.wantQual {
				t.Errorf("parseMechanism() qualifier = %v, want %v", mechanism.Qualifier, tt.wantQual)
			}
		})
	}
}

// MockDNSResolver is a mock implementation of the DNS resolver for testing
type MockDNSResolver struct {
	spfRecords map[string]string
	aRecords   map[string][]net.IP
	mxRecords  map[string][]*net.MX
}

func NewMockDNSResolver() *MockDNSResolver {
	return &MockDNSResolver{
		spfRecords: make(map[string]string),
		aRecords:   make(map[string][]net.IP),
		mxRecords:  make(map[string][]*net.MX),
	}
}

func (r *MockDNSResolver) getSPFRecord(domain string) (string, error) {
	if spf, ok := r.spfRecords[domain]; ok {
		return spf, nil
	}
	return "", nil
}

func (r *MockDNSResolver) lookupA(domain string) ([]net.IP, error) {
	if ips, ok := r.aRecords[domain]; ok {
		return ips, nil
	}
	return []net.IP{}, nil
}

func (r *MockDNSResolver) lookupMX(domain string) ([]*net.MX, error) {
	if mxs, ok := r.mxRecords[domain]; ok {
		return mxs, nil
	}
	return []*net.MX{}, nil
}

func (r *MockDNSResolver) AddSPFRecord(domain, record string) {
	r.spfRecords[domain] = record
}

func (r *MockDNSResolver) AddARecord(domain string, ip net.IP) {
	if _, ok := r.aRecords[domain]; !ok {
		r.aRecords[domain] = []net.IP{}
	}
	r.aRecords[domain] = append(r.aRecords[domain], ip)
}

func (r *MockDNSResolver) AddMXRecord(domain string, mx *net.MX) {
	if _, ok := r.mxRecords[domain]; !ok {
		r.mxRecords[domain] = []*net.MX{}
	}
	r.mxRecords[domain] = append(r.mxRecords[domain], mx)
}

func TestSPFCheckWithMock(t *testing.T) {
	// Skip this test in normal test runs as it requires mocking
	// This test is for demonstration purposes
	t.Skip("Skipping test that requires mocking DNS resolver")

	// In a real implementation, you would use a proper mocking framework
	// or dependency injection to replace the DNS resolver with a mock
}
