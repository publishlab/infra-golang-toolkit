package whois

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWhoisQuery(t *testing.T) {
	data, err := WhoisQuery("whois.norid.no", 43, "norid.no")
	assert.NotEmpty(t, data)
	assert.NoError(t, err)

	data, err = WhoisQuery("whois.radb.net", 43, "-i origin AS32934")
	assert.NotEmpty(t, data)
	assert.NoError(t, err)
}

func TestWhoisQueryError(t *testing.T) {
	data, err := WhoisQuery("whois.example.org", 43, "example.org")
	assert.Empty(t, data)
	assert.Error(t, err)
}
