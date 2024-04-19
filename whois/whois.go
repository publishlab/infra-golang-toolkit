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

func WhoisQuery(host string, port int, query string) (string, error) {
	con, err := net.Dial("tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		return "", err
	}

	defer con.Close()

	// Timeout
	err = con.SetDeadline(time.Now().Add(time.Second * 10))
	if err != nil {
		return "", err
	}

	// Write query
	_, err = con.Write([]byte(query + "\r\n"))
	if err != nil {
		return "", err
	}

	// Read response
	resp, err := io.ReadAll(con)
	if err != nil {
		return "", err
	}

	return string(resp), nil
}
