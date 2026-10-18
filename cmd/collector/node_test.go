package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestNodeCommandRequiresInClusterCredentials(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	var out, diag bytes.Buffer
	code := Main([]string{"node", "--node", "a", "--namespace", "demo", "--selector", "observe=yes", "--marker-header", "debug-token", "--marker-value", "yes"}, nil, &out, &diag)
	if code != exitInputError || out.Len() != 0 {
		t.Fatal("valid node command did not reach credential validation", code, diag.String())
	}
}

func TestNodeNamespaceScopeValidation(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	for _, tt := range []struct {
		name       string
		namespaces []string
		want       int
	}{
		{"multiple", []string{"orders", "payments"}, exitInputError},
		{"empty", nil, exitUsage},
		{"duplicate", []string{"orders", "orders"}, exitUsage},
		{"wildcard", []string{"*", "orders"}, exitUsage},
		{"comma", []string{"orders,payments"}, exitUsage},
		{"empty entry", []string{"", "orders"}, exitUsage},
	} {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"node", "--node", "a", "--selector", "observe=yes", "--marker-header", "debug-token", "--marker-value", "yes"}
			for _, ns := range tt.namespaces {
				args = append(args, "--namespace", ns)
			}
			var out, diag bytes.Buffer
			if got := Main(args, nil, &out, &diag); got != tt.want {
				t.Fatalf("got %d want %d: %s", got, tt.want, diag.String())
			}
		})
	}
}

func TestNamespaceFlagBudget(t *testing.T) {
	var ns namespaceFlags
	for i := 0; i < 32; i++ {
		if err := ns.Set(fmt.Sprintf("ns-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := ns.Set("overflow"); err == nil || len(ns) != 32 {
		t.Fatal("namespace budget not enforced")
	}
	for _, value := range []string{"UPPER", "-bad", "bad-", "a.b", strings.Repeat("a", 64)} {
		var list namespaceFlags
		if err := list.Set(value); err == nil {
			t.Fatal("invalid namespace accepted", value)
		}
	}
}

func TestNodeAcceptsOutboundDirection(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	for _, direction := range []string{"inbound", "outbound", "both"} {
		var out, diag bytes.Buffer
		got := Main([]string{"node", "--node", "a", "--namespace", "demo", "--selector", "observe=yes", "--marker-header", "debug-token", "--marker-value", "yes", "--direction", direction}, nil, &out, &diag)
		if got != exitInputError {
			t.Fatalf("direction %s rejected before credentials: %d %s", direction, got, diag.String())
		}
	}
}
