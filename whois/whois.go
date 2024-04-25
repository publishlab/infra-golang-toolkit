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
}

func Query(opts *QueryOpts) ([]byte, error) {
	if opts.Port == 0 {
		opts.Port = 43
	}

	if opts.Timeout == 0 {
		opts.Timeout = time.Second * 10
	}

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
