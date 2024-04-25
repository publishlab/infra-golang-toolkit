package whois

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestQuery(t *testing.T) {
	data, err := Query(&QueryOpts{
		Hostname: "whois.norid.no",
		Port:     43,
		Query:    "norid.no",
		Timeout:  10 * time.Second,
	})

	assert.NotEmpty(t, data)
	assert.NoError(t, err)

	data, err = Query(&QueryOpts{
		Hostname: "whois.radb.net",
		Query:    "-i origin AS32934",
	})

	assert.NotEmpty(t, data)
	assert.NoError(t, err)
}

func TestQueryError(t *testing.T) {
	data, err := Query(&QueryOpts{
		Hostname: "whois.example.org",
		Query:    "example.org",
	})

	assert.Empty(t, data)
	assert.Error(t, err)
}
