//
// Query the RADb WHOIS server for IP prefixes
//

package whois

import (
	"fmt"
	"regexp"
)

var (
	radbRoute4Re = regexp.MustCompile(`(?mi)^route:\s+([0-9.\/]+)$`)
	radbRoute6Re = regexp.MustCompile(`(?mi)^route6:\s+([0-9a-fA-F:\/]+)$`)
)

type RadbPrefixCollection struct {
	IPv4 []string
	IPv6 []string
}

func GetRadbPrefixesByAsn(asn string) (*RadbPrefixCollection, error) {
	result := &RadbPrefixCollection{}
	whois, err := WhoisQuery("whois.radb.net", 43, fmt.Sprintf("-i origin %s", asn))
	if err != nil {
		return result, err
	}

	// Grep through response for ipv4 and ipv6 prefixes
	matches4 := radbRoute4Re.FindAllStringSubmatch(whois, -1)
	matches6 := radbRoute6Re.FindAllStringSubmatch(whois, -1)

	for _, match := range matches4 {
		result.IPv4 = append(result.IPv4, match[1])
	}

	for _, match := range matches6 {
		result.IPv6 = append(result.IPv6, match[1])
	}

	return result, nil
}
