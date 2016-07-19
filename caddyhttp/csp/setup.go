package csp

import (
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("cspnonce", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// setup configures a new Templates middleware instance.
func setup(c *caddy.Controller) error {
	scopes, err := cspParse(c)
	if err != nil {
		return err
	}
	cfg := httpserver.GetConfig(c)

	cfg.AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return &NonceHandler{
			scopes: scopes,
			next:   next,
		}
	})

	return nil
}

func cspParse(c *caddy.Controller) (scopes []string, error error) {
	// TODO(wjkohnen): Actually make the scope parametrized by the Caddyfile?
	return []string{"/"}, nil
}
