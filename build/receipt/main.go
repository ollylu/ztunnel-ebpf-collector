// Command receipt 生成构建回执：绑定 revision 与制品 sha256，记录 CGO/trimpath/buildvcs 与 candidate 标签。
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

func main() {
	dist := flag.String("dist", "", "artifact directory")
	out := flag.String("out", "", "receipt path")
	revision := flag.String("revision", "unknown", "source revision")
	dirty := flag.Bool("dirty", false, "worktree dirty")
	image := flag.String("image", "", "local image tag (optional)")
	imageID := flag.String("image-id", "", "local image id (optional)")
	flag.Parse()
	if *dist == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "receipt: -dist and -out are required")
		os.Exit(2)
	}
	sums := map[string]string{}
	entries, err := os.ReadDir(*dist)
	if err != nil {
		fmt.Fprintf(os.Stderr, "receipt: %v\n", err)
		os.Exit(1)
	}
	for _, e := range entries {
		if e.IsDir() || e.Name() == filepath.Base(*out) {
			continue
		}
		p := filepath.Join(*dist, e.Name())
		sum, err := fileSHA256(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "receipt: %v\n", err)
			os.Exit(1)
		}
		sums[e.Name()] = sum
	}
	r := struct {
		SchemaVersion string            `json:"schema_version"`
		Label         string            `json:"label"`
		Revision      string            `json:"revision"`
		Dirty         bool              `json:"dirty"`
		CGOEnabled    bool              `json:"cgo_enabled"`
		Trimpath      bool              `json:"trimpath"`
		BuildVCS      bool              `json:"buildvcs"`
		Platforms     []string          `json:"platforms"`
		Image         string            `json:"image,omitempty"`
		ImageID       string            `json:"image_id,omitempty"`
		Artifacts     map[string]string `json:"artifacts_sha256"`
	}{
		SchemaVersion: "1", Label: "candidate", Revision: *revision, Dirty: *dirty,
		CGOEnabled: false, Trimpath: true, BuildVCS: false,
		Platforms: []string{"linux/arm64", "linux/amd64"}, Image: *image, ImageID: *imageID,
		Artifacts: sums,
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "receipt: %v\n", err)
		os.Exit(1)
	}
	// 原子写：先写临时文件再 rename，避免读者看到半截回执。
	tmp := *out + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "receipt: %v\n", err)
		os.Exit(1)
	}
	if err := os.Rename(tmp, *out); err != nil {
		fmt.Fprintf(os.Stderr, "receipt: %v\n", err)
		os.Exit(1)
	}
	keys := make([]string, 0, len(sums))
	for k := range sums {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Printf("receipt=%s revision=%s dirty=%v artifacts=%d\n", *out, *revision, *dirty, len(keys))
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
