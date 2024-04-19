//
// Query the RADb WHOIS server for IP prefixes
//

package whois

import (
	"fmt"
	"regexp"
	"time"
)

var (
	radbRoute4Re = regexp.MustCompile(`(?mi)^route:\s+([0-9.\/]+)$`)
	radbRoute6Re = regexp.MustCompile(`(?mi)^route6:\s+([0-9a-fA-F:\/]+)$`)
)

type RadbPrefixCollection struct {
	IPv4 [][]byte
	IPv6 [][]byte
}

type GetRadbPrefixesByAsnOpts struct {
	Asn     string
	Timeout time.Duration
}

func GetRadbPrefixesByAsn(opts *GetRadbPrefixesByAsnOpts) (*RadbPrefixCollection, error) {
	result := &RadbPrefixCollection{}
	whois, err := WhoisQuery(&WhoisQueryOpts{
		Hostname: "whois.radb.net",
		Query:    fmt.Sprintf("-i origin %s", opts.Asn),
		Timeout:  opts.Timeout,
	})

	if err != nil {
		return result, err
	}

	// Grep through response for ipv4 and ipv6 prefixes
	matches4 := radbRoute4Re.FindAllSubmatch(whois, -1)
	matches6 := radbRoute6Re.FindAllSubmatch(whois, -1)

	for _, match := range matches4 {
		result.IPv4 = append(result.IPv4, match[1])
	}

	for _, match := range matches6 {
		result.IPv6 = append(result.IPv6, match[1])
	}

	return result, nil
}
