package csp

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestZeroValue(t *testing.T) {
	empty := context.WithValue(context.Background(), "cspnonce", "invalid")
	nonce := NonceFromContext(empty)
	if nonce != "" {
		t.Errorf("Want \"\", got \"%s\".", nonce)
	}
}

func TestRoundtrip(t *testing.T) {
	next := &nextHandler{t: t}
	h := &NonceHandler{[]string{"/"}, next}
	headerHandler := &headerHandler{next: h}

	server := httptest.NewServer(headerHandler)
	defer server.Close()

	url := "http://" + server.Listener.Addr().String() + "/index.html"
	t.Log("URL", url)
	resp, err := http.Get(url)
	if err != nil {
		t.Error(err)
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
	}
	body := string(bodyBytes)

	if next.nonce == "" {
		t.Error("There is no nonce at all.")
	}
	t.Log("Context:", next.nonce)
	data, err := base64.StdEncoding.DecodeString(next.nonce)
	if err != nil {
		t.Error("`%s` is not base64: %v", next.nonce, err)
	}
	if len(data) != 16 {
		t.Errorf("Expteted 16 bytes of nonce data, got %d", len(data))
	}

	t.Log("Body:", body)
	if next.nonce != body {
		t.Errorf("Want %s in body, got %s", next.nonce, body)
	}

	header := resp.Header.Get("Content-Security-Policy")
	t.Log("Header:", header)

	headerRegex := regexp.MustCompile(`\Qdefault-src 'self'; script-src 'nonce-\E` +
		`(.+)` +
		`\Q'; style-src 'nonce-\E` +
		`(.+)` +
		`\Q';\E`)

	m := headerRegex.FindStringSubmatch(header)
	if m == nil {
		t.Fatalf("Header did not match pattern `%s`: %s", headerRegex.String(), header)
	}
	if next.nonce != m[1] || next.nonce != m[2] {
		t.Errorf("Nonce in header does not equal nonce from Context: %s not in %s", next.nonce, header)
	}
}

type nextHandler struct {
	nonce string
	t     *testing.T
}

func (n *nextHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	n.nonce = NonceFromContext(r.Context())
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, n.nonce)
	return http.StatusOK, nil
}

type headerHandler struct{ next httpserver.Handler }

func (h *headerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(contentSecurityPolicy, "default-src 'self'; script-src {cspnonce}; style-src {cspnonce};")
	_, err := h.next.ServeHTTP(w, r)
	if err != nil {
		panic(err)

	}
}
