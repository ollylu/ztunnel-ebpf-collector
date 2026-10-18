package main

import (
	"fmt"
	"io"
)

// Reporting only: target revocation and fresh-connection parsing remain owned
// by observeNode and Analyzer. Never claim HPACK state survived a byte gap.
type metadataContinuity struct{ established, gap bool }

func (s *metadataContinuity) observe(valid bool, out io.Writer) {
	if valid {
		if s.gap {
			fmt.Fprintln(out, "node_metadata_recovered recovery=new_connections existing_h2=not_resumable")
		}
		s.established = true
		s.gap = false
	} else if s.established && !s.gap {
		s.gap = true
		fmt.Fprintln(out, "node_capture_gap reason=metadata_unavailable existing_h2=not_resumable")
	}
}
