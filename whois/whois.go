//
// Send a WHOIS query and read the response
//

package whois

import (
	"fmt"
	"io"
	"net"
	"time"
)

type QueryOpts struct {
	Hostname string
	Port     int
	Query    string
	Timeout  time.Duration
	Attempts int
}

func queryHandler(opts *QueryOpts) ([]byte, error) {
	// Open connection
	con, err := net.Dial("tcp", net.JoinHostPort(opts.Hostname, fmt.Sprint(opts.Port)))
	if err != nil {
		return nil, err
	}

	defer con.Close()

	// Timeout
	err = con.SetDeadline(time.Now().Add(opts.Timeout))
	if err != nil {
		return nil, err
	}

	// Write query
	_, err = con.Write([]byte(opts.Query + "\r\n"))
	if err != nil {
		return nil, err
	}

	// Read response
	resp, err := io.ReadAll(con)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func queryLoop(opts *QueryOpts, attempt int) ([]byte, error) {
	whois, err := queryHandler(opts)

	// Retry on failure within attempt threshold
	if err != nil {
		if attempt < opts.Attempts {
			time.Sleep(time.Second * time.Duration(attempt))
			return queryLoop(opts, (attempt + 1))
		}
	}

	return whois, err
}

func Query(opts *QueryOpts) ([]byte, error) {
	if opts.Port == 0 {
		opts.Port = 43
	}

	if opts.Timeout == 0 {
		opts.Timeout = time.Second * 10
	}

	if opts.Attempts == 0 {
		opts.Attempts = 5
	}

	return queryLoop(opts, 1)
}
