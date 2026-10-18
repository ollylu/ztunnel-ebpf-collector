package main

import "testing"

func TestParsePSI(t *testing.T) {
	p := parsePSI("some avg10=1.25 avg60=0.40 avg300=0.02 total=100\nfull avg10=0.25 avg60=0.10 avg300=0.00 total=30\n")
	if p.Some != 1.25 || p.Full != 0.25 {
		t.Fatal(p)
	}
}
