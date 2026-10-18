// Temporary read-only node metrics, bounded to 55 minutes and 4MiB raw samples.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type pressure struct{ Some, Full float64 }

func parsePSI(s string) pressure {
	var p pressure
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.ParseFloat(strings.TrimPrefix(f[1], "avg10="), 64)
		if f[0] == "some" {
			p.Some = v
		}
		if f[0] == "full" {
			p.Full = v
		}
	}
	return p
}
func read(p string) string {
	b, e := os.ReadFile(p)
	if e != nil {
		return ""
	}
	return string(b)
}
func cpu() (uint64, uint64) {
	f := strings.Fields(strings.SplitN(read("/proc/stat"), "\n", 2)[0])
	var total, idle uint64
	for i, v := range f {
		if i == 0 || i > 8 {
			continue
		}
		n, _ := strconv.ParseUint(v, 10, 64)
		total += n
		if i == 4 || i == 5 {
			idle += n
		}
	}
	return total, idle
}
func memory() float64 {
	m := map[string]float64{}
	for _, l := range strings.Split(read("/proc/meminfo"), "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 {
			v, _ := strconv.ParseFloat(f[1], 64)
			m[strings.TrimSuffix(f[0], ":")] = v
		}
	}
	if m["MemTotal"] <= 0 {
		return -1
	}
	return (m["MemTotal"] - m["MemAvailable"]) / m["MemTotal"]
}
func disks() map[string][]uint64 {
	m := map[string][]uint64{}
	for _, l := range strings.Split(read("/proc/diskstats"), "\n") {
		f := strings.Fields(l)
		if len(f) < 14 {
			continue
		}
		name := f[2]
		if !strings.HasPrefix(name, "vd") && !strings.HasPrefix(name, "sd") && !strings.HasPrefix(name, "nvme") {
			continue
		}
		if _, e := os.Stat("/sys/block/" + name); e != nil {
			continue
		}
		var row []uint64
		for _, i := range []int{5, 9, 12} {
			n, _ := strconv.ParseUint(f[i], 10, 64)
			row = append(row, n)
		}
		m[name] = row
	}
	return m
}
func run() error {
	if len(os.Args) != 2 || !strings.HasPrefix(os.Args[1], "/var/tmp/ztunnel-i12-") {
		return errors.New("explicit own metrics prefix required")
	}
	prefix := os.Args[1]
	f, e := os.OpenFile(prefix+".jsonl", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	start := time.Now()
	oldT, oldI := cpu()
	oldD := disks()
	last := time.Now()
	maxima := map[string]float64{}
	var written int64
	samples := 0
	for time.Since(start) < 55*time.Minute {
		select {
		case <-time.After(5 * time.Second):
		}
		total, idle := cpu()
		delta := time.Since(last).Seconds()
		last = time.Now()
		if total == 0 || memory() < 0 {
			return errors.New("node metrics unavailable")
		}
		usage := 0.0
		if total > oldT && idle >= oldI {
			usage = 1 - float64(idle-oldI)/float64(total-oldT)
		}
		oldT, oldI = total, idle
		mem := memory()
		ps := map[string]pressure{}
		for _, k := range []string{"cpu", "memory", "io"} {
			text := read("/proc/pressure/" + k)
			if text == "" {
				return errors.New("PSI unavailable")
			}
			ps[k] = parsePSI(text)
		}
		d := disks()
		rates := map[string]map[string]float64{}
		for name, v := range d {
			if old, ok := oldD[name]; ok && v[0] >= old[0] && v[1] >= old[1] && v[2] >= old[2] {
				rates[name] = map[string]float64{"read_bytes_sec": float64(v[0]-old[0]) * 512 / delta, "write_bytes_sec": float64(v[1]-old[1]) * 512 / delta, "busy_ratio": float64(v[2]-old[2]) / (1000 * delta)}
			}
		}
		oldD = d
		vals := map[string]float64{"cpu_ratio": usage, "memory_ratio": mem, "cpu_psi_some_avg10": ps["cpu"].Some, "memory_psi_some_avg10": ps["memory"].Some, "memory_psi_full_avg10": ps["memory"].Full, "io_psi_some_avg10": ps["io"].Some, "io_psi_full_avg10": ps["io"].Full}
		for k, v := range vals {
			if v > maxima[k] {
				maxima[k] = v
			}
		}
		for _, v := range rates {
			for k, n := range v {
				if n > maxima[k] {
					maxima[k] = n
				}
			}
		}
		samples++
		row := map[string]any{"time": time.Now().UTC().Format(time.RFC3339Nano), "sample": samples, "values": vals, "disks": rates, "maxima": maxima, "elapsed_seconds": time.Since(start).Seconds()}
		b, e := json.Marshal(row)
		if e != nil {
			return e
		}
		if written+int64(len(b))+1 > 4*1024*1024 {
			return errors.New("metrics file budget")
		}
		n, e := f.Write(append(b, '\n'))
		written += int64(n)
		if e != nil {
			return e
		}
		temp := prefix + ".status.tmp"
		if e = os.WriteFile(temp, b, 0600); e != nil {
			return e
		}
		if e = os.Rename(temp, prefix+".status.json"); e != nil {
			return e
		}
		if _, e = os.Stat(prefix + ".stop"); e == nil {
			break
		}
	}
	return nil
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
