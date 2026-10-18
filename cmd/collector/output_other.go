//go:build !linux

package main

import "io"

func boundedOutput(w io.Writer) (io.Writer, func(), error) { return w, func() {}, nil }
