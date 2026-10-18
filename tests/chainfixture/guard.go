package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func quantity(v string) float64 {
	for _, u := range []struct {
		s string
		m float64
	}{{"Ki", 1024}, {"Mi", 1048576}, {"Gi", 1073741824}, {"n", 1e-9}, {"u", 1e-6}, {"m", 1e-3}} {
		if strings.HasSuffix(v, u.s) {
			f, _ := strconv.ParseFloat(strings.TrimSuffix(v, u.s), 64)
			return f * u.m
		}
	}
	f, _ := strconv.ParseFloat(v, 64)
	return f
}
func cloudGuard(ctx context.Context) error {
	base := "/var/run/secrets/kubernetes.io/serviceaccount/"
	ca, err := os.ReadFile(base + "ca.crt")
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return errors.New("guard CA invalid")
	}
	c := http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	get := func(path string, v any) error {
		token, err := os.ReadFile(base + "token")
		if err != nil {
			return err
		}
		r, _ := http.NewRequestWithContext(ctx, "GET", "https://"+os.Getenv("KUBERNETES_SERVICE_HOST")+":"+os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")+path, nil)
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
		resp, err := c.Do(r)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("cloud guard API status %d", resp.StatusCode)
		}
		return json.NewDecoder(resp.Body).Decode(v)
	}
	hot := 0
	for ctx.Err() == nil {
		var nodes struct {
			Items []struct {
				Metadata struct{ Name string }
				Status   struct {
					Allocatable map[string]string
					Conditions  []struct{ Type, Status string }
				}
			}
		}
		if err := get("/api/v1/nodes", &nodes); err != nil {
			return err
		}
		cap := map[string]map[string]string{}
		for _, n := range nodes.Items {
			cap[n.Metadata.Name] = n.Status.Allocatable
			for _, c := range n.Status.Conditions {
				if (c.Type == "Ready" && c.Status != "True") || (strings.HasSuffix(c.Type, "Pressure") && c.Status == "True") {
					return errors.New("node health protection")
				}
			}
		}
		var metrics struct {
			Items []struct {
				Metadata struct{ Name string }
				Usage    map[string]string
			}
		}
		if err := get("/apis/metrics.k8s.io/v1beta1/nodes", &metrics); err != nil {
			return err
		}
		over := false
		for _, n := range metrics.Items {
			a := cap[n.Metadata.Name]
			cpu, mem := quantity(a["cpu"]), quantity(a["memory"])
			if cpu <= 0 || mem <= 0 {
				return errors.New("unknown node capacity")
			}
			if quantity(n.Usage["cpu"])/cpu > .85 || quantity(n.Usage["memory"])/mem > .85 {
				over = true
			}
		}

		if ns := os.Getenv("SENSOR_NAMESPACE"); ns != "" {
			var pods struct {
				Items []struct {
					Status struct {
						Phase             string
						ContainerStatuses []struct{ Ready bool }
					}
				}
			}
			if err := get("/api/v1/namespaces/"+ns+"/pods", &pods); err != nil {
				return err
			}
			if len(pods.Items) == 0 {
				return errors.New("collector pods missing")
			}
			for _, p := range pods.Items {
				if p.Status.Phase != "Running" {
					return errors.New("collector protection or unavailable")
				}
				for _, c := range p.Status.ContainerStatuses {
					if !c.Ready {
						return errors.New("collector not ready: stop load")
					}
				}
			}
		}
		if over {
			hot++
		} else {
			hot = 0
		}
		if hot >= 3 {
			return errors.New("node CPU/memory 85% protection")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(2 * time.Second):
		}
	}
	return nil
}
