package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gookit/webproxy"
)

var (
	url1 = "https://inhere.github.io/index.html"
	url2 = "http://yzone.net/page/about-me"
)

// go run ./_examples/proxy.go
func main() {
	mux := http.DefaultServeMux

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_,_ = w.Write([]byte("hello"))
	})

	all1 := webproxy.Target(url1, webproxy.Options{Debug: true})
	mux.HandleFunc("/pxy1", all1.HandlerFunc())

	all2 := webproxy.Target(url2, webproxy.Options{Debug: true})
	mux.HandleFunc("/pxy2", all2.HandlerFunc())

	// as a middleware
	proxy := webproxy.New("/api", webproxy.Options{
		Debug:  true,
		Target: "http://yzone.net",
	})

	fmt.Println("Server listening http://127.0.0.1:18020")
	log.Fatal(http.ListenAndServe("127.0.0.1:18020", proxy.Middleware(mux)))
}
