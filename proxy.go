// Package httpProxy is a simple http proxy tool.
//
// Refer:
// 	https://github.com/nodejitsu/node-http-proxy
// 	https://github.com/chimurai/http-proxy-middleware
// 	"golang.org/x/net/proxy" -> proxy.SOCKS5()
//
// 使用说明：
//
// 1. 作为中间件 - 匹配成功就代理请求，否则跳过当前请求。
//
// 	proxy.New("/api", some options)
// 	proxy.New([]string{"/api", "/v1/api"}, some options)
//
// 2. 直接作为路由path handler - 代理此路由下的所有请求(相当于作为中间件时，ctx为一个url path)
//
// 	router.GET("/api", proxy.All(some options))
// 	http.HandleFunc("/api", proxy.All(some options))
//
// 参数说明：
//
// proxy.New() 接收两个参数：第一个是要匹配的信息，第二个是一些选项设置
//
// 关于参数 'ctx'，它允许为:
// 	empty:
// 		nil - matches any path, all requests will be proxied.
// 	path matching(string - a URL path, support wildcard):
// 		"/", "**" - matches any path, all requests will be proxied.
// 		"/api" - matches paths starting with /api
// 		"**/*.html" - matches any path which ends with .html
// 		"/*.html" - matches paths directly under path-absolute
// 		"!**/bad.json" - exclusion
// 	multiple path matching([]string - multi URL path, support wildcard).
// 		[]string{"/api", "/v1/api", "/some/**/special-api"}
// 	custom validate func:
// 		FilterFunc - must be type of FilterFunc. return True, proxy current request
package httpProxy

import (
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
)

// the Proxy ctx data type name
const (
	CtxIsEmpty   = "empty"
	CtxIsString  = "string"
	CtxIsStrings = "strings"
	CtxIsFilter  = "func"
)

// Proxy definition
type Proxy struct {
	// the ReverseProxy instance
	rp *httputil.ReverseProxy
	// options for proxy
	opts *Options
	// internal. parsed from opts.Target
	target *url.URL
	// context use for match request.
	ctx interface{}
	// the ctx data type. allow in: "empty", "string", "strings", "func"
	ctxType string
	// compiled ctx matchers
	ctxMatchers map[string]*regexp.Regexp
	// logger
	logger *log.Logger
}

// Options for proxy.
type Options struct {
	// open debug
	Debug bool
	// WS enable webSocket proxy
	WS bool
	// Target url string. eg. "http://www.example.org"
	// Notice:
	// 	Target and Forward cannot be both missing
	Target string
	// Forward url string.
	Forward string
	// IgnorePath specify whether you want to ignore the proxy path of the incoming request. Default: false
	IgnorePath bool
	// ChangeOrigin changes the origin of the host header to the target URL. Default: false
	// for vhosted sites, changes host header to match to target's host
	ChangeOrigin bool
	// Auth is basic authentication i.e. 'user:password' to compute an Authorization header.
	Auth string
	// WS bool
	// PathRewrite url path rewrite
	// 	{
	//      '^/api/old-path' : '/api/new-path',     // rewrite path
	//      '^/api/remove/path' : '/path'           // remove base path
	// 		'^/' : '/basePath/'  					// add base path
	//   },
	PathRewrite map[string]string
	LogLevel    int
	// LogOutput
	// Example:
	//	LogOutput = os.Stdout
	//	LogOutput = new(bytes.Buffer)
	//	LogOutput, _ = os.OpenFile("proxy.log", os.O_RDWR|os.O_CREATE, os.ModePerm)
	LogOutput io.Writer
	//
	Events map[string]func(args ...interface{}) error
	// Routes table, if match success, will override Target.
	//
	// Example:
	// 	{
	// 		// when request.headers.host == 'dev.localhost:3000',
	// 		// override target 'http://www.example.org' to 'http://localhost:8000'
	// 		"dev.localhost:3000" : "http://localhost:8000"
	// 	}
	Routes map[string]string
}

const (
	anyMatch = `[^/]+`
	allMatch = `.+`
)

// FilterFunc custom filter to check if it should be proxy or not
type FilterFunc func(path string, r *http.Request) bool

// proxyRes -> ModifyResponse
var proxyEvents = []string{"error", "proxyReq", "proxyReqWs", "proxyRes", "open", "close"}

var (
	matchAll = map[string]uint8{"": 1, "/": 1, "**": 1}
)

// New a proxy instance.
func New(ctx interface{}, opts Options) *Proxy {
	opts.Target = strings.TrimSpace(opts.Target)
	if opts.Target == "" {
		panic("target url cannot be empty")
	}

	var err error

	p := &Proxy{ctx: ctx, opts: &opts}
	p.checkCtxType()

	// parse target url to url.URL instance
	p.target, err = url.Parse(p.opts.Target)
	if err != nil {
		panic(err)
	}

	p.createReverseProxy(p.target)

	return p
}

// All requests will be proxy
func All(opts Options) *Proxy {
	return New(nil, opts)
}

// Target requests will be proxy to the target URL
func Target(url string, opts ...Options) *Proxy {
	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	} else {
		opt = Options{}
	}

	opt.Target = url
	return New(nil, opt)
}

func (p *Proxy) init(opts *Options) {
	if opts.LogOutput != nil {
		p.logger = log.New(opts.LogOutput, "httpProxy", log.Lshortfile)
	}
}

func (p *Proxy) checkCtxType() {
	if p.ctx == nil {
		p.ctxType = CtxIsEmpty
		return
	}

	switch p.ctx.(type) {
	case string:
		path := strings.TrimSpace(p.ctx.(string))
		p.ctx = path
		p.ctxType = CtxIsString
		p.compilePathMatchers([]string{path})
	case []string:
		p.ctxType = CtxIsStrings
		p.compilePathMatchers(p.ctx.([]string))
	case FilterFunc:
		p.ctxType = CtxIsFilter
	default:
		panic("invalid data type of the 'ctx', allow: string, strings, func")
	}
}

func (p *Proxy) compilePathMatchers(paths []string) {
	p.ctxMatchers = make(map[string]*regexp.Regexp, 0)

	for _, path := range paths {
		// eg "", "**", "/"
		if _, ok := matchAll[path]; ok {
			continue
		}

		raw := path

		// eg "!/api/users"
		if path[0] == '!' {
			path = path[1:]
		}

		// don't need compile regex. eg "/api"
		if p.isFixedPath(path) {
			continue
		}

		// ".html" -> "\.html"
		path = quotePointChar(path)

		// has wildcard "*"
		if strings.IndexByte(path, '*') > -1 {
			// has match all wildcard "**"
			regex := strings.Replace(path, "**", allMatch, -1)
			// has match any wildcard "*"
			regex = strings.Replace(regex, "*", anyMatch, -1)

			p.ctxMatchers[raw] = regexp.MustCompile("^" + regex)
		} else {
			p.ctxMatchers[raw] = regexp.MustCompile("^" + path)
		}
	}
}

func (p *Proxy) createReverseProxy(target *url.URL) {
	targetQuery := target.RawQuery

	p.rp = &httputil.ReverseProxy{
		ErrorLog: p.logger,
		// you can modify request data before request target host.
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)

			if targetQuery == "" || req.URL.RawQuery == "" {
				req.URL.RawQuery = targetQuery + req.URL.RawQuery
			} else {
				req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
			}

			if _, ok := req.Header["User-Agent"]; !ok {
				// explicitly disable User-Agent so it's not set to default value
				req.Header.Set("User-Agent", "")
			}

			// for vhosted sites, changes host header to match to target's host
			if p.opts.ChangeOrigin {
				req.Header.Set("Host", target.Host) // add Port: target.Port
			}

			//
			p.emit("proxyReq", req)
		},
		// you can modify response data before respond to client
		ModifyResponse: func(res *http.Response) error {
			//
			p.emit("proxyRes", res)
			return nil
		},
	}
}

// eg "!/api/users"
func (p *Proxy) isExclusion(path string) bool {
	return path[0] == '!'
}

// isFixedPath. eg "/api"
func (p *Proxy) isFixedPath(path string) bool {
	return strings.IndexByte(path, '*') == -1
}

/*************************************************************
 * request handle
 *************************************************************/

// Middleware of the interface http.Handler
func (p *Proxy) Middleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.opts.Debug {
			log.Printf("Received request [%s] %s %s\n", r.Method, r.Host, r.RemoteAddr)
		}

		// match
		if p.shouldProxy(r) {
			p.ServeHTTP(w, r)
		} else {
			h.ServeHTTP(w, r) // skip
		}
	})
}

// HandlerFunc return http.HandlerFunc
func (p *Proxy) HandlerFunc() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.ServeHTTP(w, r)
	})
}

// ServeHTTP handle request
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.opts.Debug {
		log.Printf(
			"Proxy the request %s %s %s to %s\n",
			r.Method, r.Host, r.RemoteAddr,
			p.opts.Target,
		)
	}

	p.rp.ServeHTTP(w, r)
}

/*************************************************************
 * match request
 *************************************************************/

// shouldProxy check
func (p *Proxy) shouldProxy(r *http.Request) bool {
	switch p.ctxType {
	case CtxIsEmpty:
		return true
	case CtxIsString:
		return p.matchSingleString(p.ctx.(string), r)
	case CtxIsStrings:
		return p.matchMultiStrings(p.ctx.([]string), r)
	case CtxIsFilter: // custom filter check
		filter := p.ctx.(FilterFunc)
		return filter(r.URL.Path, r)
	}

	return false
}

// match single URL path string.
// Rules:
// 	path matching(string - a URL path, support wildcard):
// 		"/", "**" - matches any path, all requests will be proxied.
// 		"/api" - matches paths starting with /api
// 		"**/*.html" - matches any path which ends with .html
// 		"/*.html" - matches paths directly under path-absolute
// 		"!**/bad.json" - exclusion
func (p *Proxy) matchSingleString(path string, r *http.Request) bool {
	if _, ok := matchAll[path]; ok {
		return true
	}

	raw := path
	reqPath := r.URL.Path
	okReturn := true

	// eg "!/api/users"
	if path[0] == '!' {
		path = path[1:]
		okReturn = false
	}

	// eg "/api"
	if p.isFixedPath(path) && strings.HasPrefix(reqPath, path) {
		return okReturn
	}

	matcher, ok := p.ctxMatchers[raw]
	if ok && matcher.MatchString(reqPath) {
		return okReturn
	}

	return false
}

// match multi URL path strings
func (p *Proxy) matchMultiStrings(paths []string, r *http.Request) bool {
	for _, path := range paths {
		if p.matchSingleString(path, r) {
			return true
		}
	}

	return false
}

// WEB request proxy
func (p *Proxy) WEB() {

}

// WS request proxy
func (p *Proxy) WS() {

}

// emit a event
func (p *Proxy) emit(event string, args ...interface{}) {

}

// Options get
func (p *Proxy) Options() Options {
	return *p.opts
}

func quotePointChar(path string) string {
	if strings.IndexByte(path, '.') > 0 {
		// "about.html" -> "about\.html"
		return strings.Replace(path, ".", `\.`, -1)
	}

	return path
}

func singleJoiningSlash(a, b string) string {
	aAlash := strings.HasSuffix(a, "/")
	bAlash := strings.HasPrefix(b, "/")
	switch {
	case aAlash && bAlash:
		return a + b[1:]
	case !aAlash && !bAlash:
		return a + "/" + b
	}
	return a + b
}

// MultiHostReverseProxy create a global reverse proxy.
// usage:
// 	rp := MultiHostReverseProxy(&url.URL{
// 		Scheme: "http",
// 		Host:   "localhost:9091",
// 	}, &url.URL{
// 		Scheme: "http",
// 		Host:   "localhost:9092",
// 	})
// 	log.Fatal(http.ListenAndServe(":9090", rp))
func MultiHostReverseProxy(targets ...*url.URL) *httputil.ReverseProxy {
	if len(targets) == 0 {
		panic("Please add at least one remote target server")
	}

	var target *url.URL

	// if only one target
	if len(targets) == 1 {
		target = targets[0]
	}

	director := func(req *http.Request) {
		if len(targets) > 1 {
			target = targets[rand.Int()%len(targets)]
		}

		fmt.Printf("Received request %s %s %s\n", req.Method, req.Host, req.RemoteAddr)

		targetQuery := target.RawQuery

		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = target.Path
		// req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)

		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			// explicitly disable User-Agent so it's not set to default value
			req.Header.Set("User-Agent", "")
		}
	}

	return &httputil.ReverseProxy{Director: director}
}
