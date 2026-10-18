package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestMetadataGapReportedOnceAndRecoveryDoesNotPromiseOldStreams(t *testing.T) {
	var s metadataContinuity
	var out bytes.Buffer
	for _, valid := range []bool{false, false, true, true, false, false, true, true} {
		s.observe(valid, &out)
	}
	got := out.String()
	if strings.Count(got, "node_capture_gap ") != 1 || strings.Count(got, "node_metadata_recovered ") != 1 || !strings.Contains(got, "existing_h2=not_resumable") || !strings.Contains(got, "recovery=new_connections") {
		t.Fatalf("missing bounded gap/recovery diagnostics: %q", got)
	}
}
