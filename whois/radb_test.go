package whois

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRadbPrefixesByAsn(t *testing.T) {
	tests := []string{
		"AS8075",  // Microsoft
		"AS15169", // Google
		"AS32934", // Facebook
	}

	for _, asn := range tests {
		resp, err := RadbPrefixesByAsn(&RadbPrefixesByAsnOpts{Asn: asn})
		assert.NoError(t, err)
		assert.NotEmpty(t, resp.IPv4)
		assert.NotEmpty(t, resp.IPv6)
	}
}

func TestRadbPrefixesByAsnError(t *testing.T) {
	resp, err := RadbPrefixesByAsn(&RadbPrefixesByAsnOpts{Asn: "AS0"})
	assert.NoError(t, err)
	assert.Empty(t, resp.IPv4)
	assert.Empty(t, resp.IPv6)
}
