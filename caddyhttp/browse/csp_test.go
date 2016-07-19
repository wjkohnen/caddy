package browse

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"text/template"

	"github.com/mholt/caddy/caddyhttp/csp"
	"github.com/mholt/caddy/caddyhttp/httpserver"
	"github.com/mholt/caddy/caddyhttp/staticfiles"
)

func TestCSPTemplate(t *testing.T) {
	tmpl, err := template.ParseFiles("testdata/csp.tpl")
	if err != nil {
		t.Fatalf("An error occured while parsing the template: %v", err)
	}

	b := Browse{
		Next: httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
			t.Fatal("dead")
			return 0, nil
		}),
		Configs: []Config{
			{
				PathScope: "/photos",
				Fs:        staticfiles.FileServer{Root: http.Dir("./testdata")},
				Template:  tmpl,
			},
		},
	}

	cspNonceHandler := csp.NewNonceHandler([]string{"/photos"}, b)

	req, err := http.NewRequest("GET", "/photos/", nil)
	if err != nil {
		t.Fatalf("Test: Could not create HTTP request: %v", err)
	}
	req.Header.Set("Content-Security-Policy", "anything")
	rec := httptest.NewRecorder()
	code, err := cspNonceHandler.ServeHTTP(rec, req)
	if err != nil {
		t.Errorf("Handler returned code %d, error: %v", code, err)
	}
	if code != http.StatusOK {
		t.Errorf("Want StatusOK (200), got %d", code)
	}

	// 24 characters of Base64URL alphabet (16 unencoded bytes + padding)
	noncePattern := `[a-zA-Z0-9\-_=]{24}`
	pattern := `\Q<style nonce="\E` + noncePattern + `\Q">* { padding: 0; margin: 0; }</style>\E`

	respBody := rec.Body.Bytes()
	matches, err := regexp.Match(pattern, respBody)
	if err != nil {
		t.Error(err)
	}
	if !matches {
		t.Fatalf("Test: Body does not match pattern %s", string(respBody))
	}
}
