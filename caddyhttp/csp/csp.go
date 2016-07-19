// Package csp provides a directive for adding nonce-source to Content-Security-
// Policy (CSP) headers and templates.
//
// The NonceHandler creates a nonce value per request and stores it in the
// request context. Plugins can read the nonce value with the NonceFromContext
// function. The nonce is in the base64 encoded string form and can be inserted
// into documents as is.
//
// Any occurence of "{cspnonce}" in the CSP header will be replaced by a nonce
// source expression. Therefore you need to explicitly configure the header
// string with that placeholder. The cspnonce handler will exit fast if the
// CSP header is not set, i.e. scoping is effectively inherited by the header
// directive's CSP header.
//
// Example Caddyfile snippet:
//
//      cspnonce
//      header / {
//          Content-Security-Policy "default-src 'self'; script-src 'self' {cspnonce}; style-src 'self' {cspnonce};"
//      }
//
// There are two ways to make the value available to templates:
//
// 1. Pipeline
//
//    Add a field to a template execution data struct or a key-value to a
//    template execution data map.
//
//    data := struct{CSPNonce string}{CSPNonce: csp.NonceFromContext(r.Context())}
//    theTemplate.Execute(w, data)
//
//    Insert the value into the document with the .CSPNonce pipeline:
//
//    <style{{if .CSPNonce}} nonce="{{.CSPNonce}}"{{end}}> ... </style>
//
// 2. Function
//
//    Extend the template function map with a cspnonce function.
//
//      theTemplate.Funcs(template.FuncMap{
//          "cspnonce": func () string { return csp.NonceFromContext(r.Context()) },
//      })
//      theTemplate.Execute(w, nil)
//
//    Insert the value into the document using the "cspnonce" function:
//
//      <style{{if cspnonce}} nonce="{{cspnonce}}"{{end}}> ... </style>
//
// In both cases if a nonce is not available {{if}} will evaluate to false.
//
// Because the CSP standard requires base 64 standard encoding, a nonce string
// may contain a '+' plus sign which the Go templating engine will by default
// escapes to "&#43;". The standard does not clearly document how to handle this.
// However, tests with Firefox 47 and Chrome 51 suggest transparent unescaping.
//
// WARNING:
//
// The nonce source directive requires Content Security Policy Level 2. Not all
// browsers support CSP2 yet, see http://caniuse.com/#feat=contentsecuritypolicy2
// Most notably Internet Explorer and mobile browsers are lacking (2016-07-19).
package csp

import (
	"context"
	"net/http"

	"github.com/mholt/caddy/caddyhttp/csp/intern/nonce"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// NonceHandler creates a nonce value per request and stores it in the
// request context. Any occurence of "{cspnonce}" in the
// Content-Security-Policy header will be replaced by a nonce source expression.
type NonceHandler struct {
	scopes []string
	next   httpserver.Handler
}

// ServeHTTP inserts a nonce into the request context and substitutes {cspnonce} in the
// Content-Security-Policy header. Will no-op fast, if the header has not been set.
func (n *NonceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	header := w.Header().Get(contentSecurityPolicy)
	if header != "" {
		for _, scope := range n.scopes {
			if httpserver.Path(r.URL.Path).Matches(scope) {
				nonce := nonce.New()
				nonceSourceExpr := "'nonce-" + nonce + "'"

				replacer := httpserver.NewReplacer(r, nil, "")
				replacer.Set("cspnonce", nonceSourceExpr)

				w.Header().Set(contentSecurityPolicy, replacer.Replace(header))
				ctx := context.WithValue(r.Context(), contextKeyNonce, nonce)
				r = r.WithContext(ctx)

				break
			}
		}
	}

	return n.next.ServeHTTP(w, r)
}

// NonceFromContext returns the nonce from the context. The nonce string is
// base64 encoded with the standard alphabet. Returns empty string if
// no nonce available.
func NonceFromContext(ctx context.Context) string {
	nonce, _ := ctx.Value(contextKeyNonce).(string)
	return nonce
}

type contextKey struct{ name string }

// allocation free context key, see net/http/server.go and https://gist.github.com/wjkohnen/38aa83244256cdbbf74f6d8609a7dfbd
var contextKeyNonce = &contextKey{name: "cspnonce"}

const contentSecurityPolicy = "Content-Security-Policy"
