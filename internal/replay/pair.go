package replay

import "io"

// DecodePair reuses strict HTTP framing and marker rules for a complete pair.
// The caller must supply verified source and endpoint metadata separately.
func DecodePair(request, response string, marker Marker, id string) []Record {
	if marker.Validate() != nil {
		return nil
	}
	req, ok := parseMessage(request, true, "")
	if !ok || !marker.Match(req.headers) {
		return nil
	}
	resp, ok := parseMessage(response, false, req.method)
	if !ok {
		return nil
	}
	return []Record{requestRecord(id, req), responseRecord(id, resp)}
}

// WriteRecord enforces the same output byte bound for replay and live capture.
func WriteRecord(w io.Writer, r Record) error { return writeRecord(w, r) }
