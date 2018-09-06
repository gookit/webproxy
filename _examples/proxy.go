package main

import (
	"fmt"
	"github.com/gookit/httpProxy"
	"log"
	"net/http"
)

var (
	url1 = "https://inhere.github.io/index.html"
	url2 = "http://yzone.net/page/about-me"
)

// go run ./_examples/proxy.go
func main() {
	mux := http.DefaultServeMux

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	})

	all1 := httpProxy.Target(url1, httpProxy.Options{Debug: true})
	mux.HandleFunc("/pxy1", all1.HandlerFunc())

	all2 := httpProxy.Target(url2, httpProxy.Options{Debug: true})
	mux.HandleFunc("/pxy2", all2.HandlerFunc())

	// as a middleware
	proxy := httpProxy.New("/api", httpProxy.Options{
		Debug:  true,
		Target: "http://yzone.net",
	})

	fmt.Println("Server listening http://127.0.0.1:18020")
	log.Fatal(http.ListenAndServe("127.0.0.1:18020", proxy.Middleware(mux)))
}
