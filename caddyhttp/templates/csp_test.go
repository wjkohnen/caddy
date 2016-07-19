package templates

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"testing"

	"github.com/mholt/caddy/caddyhttp/csp"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestCSPTemplate(t *testing.T) {
	tmplroot := Templates{
		Next: httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
			t.Fatal("unreachable")
			return 0, nil
		}),
		Rules:   []Rule{{Extensions: []string{".html"}}},
		Root:    "./testdata",
		FileSys: http.Dir("./testdata"),
		BufPool: bufPool,
	}
	cspnonceHandler := csp.NewNonceHandler([]string{"/"}, tmplroot)

	req, err := http.NewRequest("GET", "/csp.html", nil)
	if err != nil {
		t.Fatalf("Test: Could not create HTTP request: %v", err)
	}
	req.Header.Set("Content-Security-Policy", "anything")
	rec := httptest.NewRecorder()
	cspnonceHandler.ServeHTTP(rec, req)

	noncePattern := `[a-zA-Z0-9\-_=]{24}` // 24 characters of Base64URL alphabet (16 unencoded bytes + padding)
	pattern := `\Q` + `<!DOCTYPE html><html><head><title>csp test</title><style nonce="` + `\E` +
		noncePattern +
		`\Q` + `">* { padding: 0; margin: 0; }</style></head><body>csp test</body></html>` + `\E`

	respBody := rec.Body.Bytes()
	matches, err := regexp.Match(pattern, respBody)
	if err != nil {
		t.Error(err)
	}
	if !matches {
		t.Fatalf("Test: Body does not match pattern %s", string(respBody))
	}
}

var bufPool = &sync.Pool{New: func() interface{} { return new(bytes.Buffer) }}
