// A bounded, explicit real-traffic fixture; never used as a capture event source.
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "idle" {
		time.Sleep(20 * time.Minute)
		return
	}
	if len(os.Args) > 2 && os.Args[1] == "client" {
		client := http.Client{Timeout: 5 * time.Second}
		for _, marked := range []bool{true, false} {
			path := "/unmarked"
			if marked {
				path = "/marked"
			}
			req, e := http.NewRequest("GET", os.Args[2]+path, nil)
			if e != nil {
				panic(e)
			}
			if marked {
				req.Header.Set("Debug-Token", "yes")
			}
			r, e := client.Do(req)
			if e != nil {
				fmt.Fprintln(os.Stderr, e)
				os.Exit(1)
			}
			_, _ = io.Copy(io.Discard, r.Body)
			r.Body.Close()
			fmt.Println(path, r.StatusCode)
		}
		return
	}
	server := http.Server{Addr: ":8080", ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, MaxHeaderBytes: 8192, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := "reply:" + r.URL.Path
		w.Header().Set("Content-Length", fmt.Sprint(len(b)))
		_, _ = io.WriteString(w, b)
	})}
	if e := server.ListenAndServe(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
