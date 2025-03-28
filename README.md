# SPF Validation Library for Go

This library provides SPF (Sender Policy Framework) validation functionality according to [RFC 7208](https://datatracker.ietf.org/doc/html/rfc7208). It allows you to check if an IP address is authorized to send emails from a specific domain by validating against the domain's SPF records.

## Features

- Complete implementation of RFC 7208 SPF validation
- Support for all SPF mechanisms: `all`, `ip4`, `ip6`, `a`, `mx`, `include`, `exists`, `ptr`
- Support for all qualifiers: `+` (pass), `-` (fail), `~` (softfail), `?` (neutral)
- Recursive resolution of `include:` directives
- Support for `redirect` modifier
- Multiple DNS server support for lookups
- Proper handling of DNS lookup limits (max 10 lookups per check)
- Debug mode for hierarchical mechanism evaluation output
- Clear result codes as defined in RFC 7208

## Installation

```bash
go get github.com/jwillberg/spf
```

## Usage

### Basic Usage

```go
package main

import (
    "fmt"
    "github.com/jwillberg/spf"
)

func main() {
    // Check if IP 192.168.1.1 is authorized to send emails from example.com
    result, err := spf.SPFCheck("192.168.1.1", "example.com")
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }

    fmt.Printf("SPF check result: %s\n", result)

    // Handle different result types
    switch result {
    case spf.ResultPass:
        fmt.Println("The IP is authorized to send mail from this domain")
    case spf.ResultFail:
        fmt.Println("The IP is NOT authorized to send mail from this domain")
    case spf.ResultSoftFail:
        fmt.Println("The IP is probably not authorized (weak policy)")
    case spf.ResultNeutral:
        fmt.Println("The domain explicitly states no assertion about this IP")
    case spf.ResultNone:
        fmt.Println("No SPF record found or no valid domain")
    case spf.ResultTempError:
        fmt.Println("Temporary error occurred during SPF check")
    case spf.ResultPermError:
        fmt.Println("Permanent error occurred during SPF check")
    }
}
```

### Result Types

The library returns one of the following result types as defined in RFC 7208 section 2.6:

- `none`: No SPF records found or no valid domain
- `neutral`: Domain explicitly states no assertion
- `pass`: IP is authorized to send mail from this domain
- `fail`: IP is not authorized to send mail from this domain
- `softfail`: IP is probably not authorized (weak policy)
- `temperror`: Temporary error (generally DNS) while performing the check
- `permerror`: Permanent error (invalid SPF record) that requires DNS operator intervention

## Command Line Tool

The library includes a simple command-line tool to test SPF validation:

```bash
go run main.go [--debug] <ip> <domain>
```

Example with debug output:

```bash
go run main.go --debug 52.103.0.1 willberg.me
```

### Example Debug Output

```
Checking SPF for IP 52.103.0.1 and domain willberg.me
  ↳ SPF: v=spf1 a mx ip4:37.97.172.152 ip6:2a01:7c8:aac0:79:5054:ff:fea1:15a0 ip4:217.77.192.9 ip4:217.77.193.9 include:spf.protection.outlook.com ~all
    ↳ a → not matched
    ↳ mx → not matched
    ↳ ip4:37.97.172.152/32 → not matched
    ↳ ip6:2a01:7c8:aac0:79:5054:ff:fea1:15a0/128 → not matched
    ↳ ip4:217.77.192.9/32 → not matched
    ↳ ip4:217.77.193.9/32 → not matched
  ↳ include:spf.protection.outlook.com
  Checking SPF for IP 52.103.0.1 and domain spf.protection.outlook.com
    ↳ SPF: v=spf1 ip4:40.92.0.0/15 ip4:40.107.0.0/16 ip4:52.100.0.0/15 ip4:52.102.0.0/16 ip4:52.103.0.0/17 ip4:104.47.0.0/17 ip6:2a01:111:f400::/48 ip6:2a01:111:f403::/49 ip6:2a01:111:f403:8000::/51 ip6:2a01:111:f403:c000::/51 ip6:2a01:111:f403:f000::/52 -all
      ↳ ip4:40.92.0.0/15 → not matched
      ↳ ip4:40.107.0.0/16 → not matched
      ↳ ip4:52.100.0.0/15 → not matched
      ↳ ip4:52.102.0.0/16 → not matched
      ↳ ip4:52.103.0.0/17 → MATCHED (pass)
    ↳ include:spf.protection.outlook.com → MATCHED (pass)
SPF check result for IP 52.103.0.1 sending from domain willberg.me: pass
```

## Implementation Details

The library uses multiple DNS servers for lookups:

```go
var spfDNSServers = []string{"8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"}
```

It implements all SPF mechanisms as specified in RFC 7208:

- `all`: Matches always
- `ip4`: Matches IPv4 addresses and networks
- `ip6`: Matches IPv6 addresses and networks
- `a`: Matches if the IP is one of the A records for the domain
- `mx`: Matches if the IP is one of the mail exchangers for the domain
- `include`: Includes another domain's SPF policy
- `exists`: Matches if the specified domain exists
- `ptr`: Matches if a PTR record for the IP resolves to the domain (deprecated)
- `redirect`: Redirects evaluation to another domain

## License

MIT License
