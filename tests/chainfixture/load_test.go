package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestLoadKeepsFivePercentAndChecksResponses(t *testing.T) {
	var n, m atomic.Int64
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		if r.Header.Get("Debug-Token") == "yes" {
			m.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"mysql":1}`))
	}))
	defer s.Close()
	st, err := runLoad(context.Background(), s.URL, 20, time.Second)
	if err != nil || n.Load() != 20 || m.Load() != 1 || st.Success != 20 || st.Failed != 0 {
		t.Fatal("wrong actual load or coloring", st, n.Load(), m.Load(), err)
	}
}
