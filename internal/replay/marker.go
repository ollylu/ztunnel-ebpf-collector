package replay

import (
	"errors"
	"strings"
)

// Marker matches exactly one initial request header. It is not connection state.
type Marker struct {
	Header string
	Value  string
}

func (m Marker) Validate() error {
	if len(m.Header) == 0 || len(m.Header) > 128 || len(m.Value) == 0 || len(m.Value) > 256 || strings.Trim(m.Value, " \t") != m.Value {
		return errors.New("invalid marker configuration")
	}
	for _, c := range m.Header {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
			return errors.New("invalid marker header")
		}
	}
	switch strings.ToLower(m.Header) {
	case "host", "content-length", "transfer-encoding", "connection", "trailer", "upgrade":
		return errors.New("protocol header cannot be a marker")
	}
	for _, c := range m.Value {
		if c < 32 || c > 126 {
			return errors.New("invalid marker value")
		}
	}
	return nil
}
func (m Marker) Match(headers map[string][]string) bool {
	var values []string
	for k, v := range headers {
		if strings.EqualFold(k, m.Header) {
			values = append(values, v...)
		}
	}
	return len(values) == 1 && strings.Trim(values[0], " \t") == m.Value
}
