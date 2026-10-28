package server

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"

	"github.com/dexidp/dex/server/oauth2"
	"github.com/dexidp/dex/storage"
)

// directIssuers serves direct connector issuers: every connector is
// additionally served as a full issuer at "( path )/( connector id )", whose
// login flow is pinned to that connector instead of offering the selection
// screen. Each issuer is built on first use and kept for the server's lifetime.
//
// Redirect connectors still return to the primary issuer's callback (the
// redirect URI they are registered with), which hands the flow back to the
// direct issuer it started on (see authflow/direct.go).
type directIssuers struct {
	// path is the path direct issuers are served under, e.g. "/dex-direct".
	path string
	// primary is the primary issuer's URL; direct issuers share its origin.
	primary oauth2.IssuerURL
	storage storage.Storage
	logger  *slog.Logger
	// build builds the direct issuer of a connector.
	build func(connectorID string) (*Server, error)

	mu      sync.Mutex
	servers map[string]*Server
}

// issuerURL is the issuer URL of a connector's direct issuer.
func (d *directIssuers) issuerURL(connectorID string) oauth2.IssuerURL {
	u := d.primary.URL
	u.Path = path.Join(d.path, connectorID)
	u.RawPath = ""
	return oauth2.IssuerURL{URL: u}
}

func (d *directIssuers) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rest, ok := strings.CutPrefix(r.URL.EscapedPath(), d.path+"/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	connectorID, _, _ := strings.Cut(rest, "/")
	// Only IDs that need no escaping are served, so the issuer path matches the
	// encoded request path the issuer's router sees.
	if connectorID == "" || connectorID == "." || connectorID == ".." || url.PathEscape(connectorID) != connectorID {
		http.NotFound(w, r)
		return
	}

	// Checked on every request: connectors can be removed at runtime.
	if _, err := d.storage.GetConnector(r.Context(), connectorID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		d.logger.ErrorContext(r.Context(), "failed to get connector for direct issuer", "connector_id", connectorID, "err", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	srv, err := d.server(connectorID)
	if err != nil {
		d.logger.ErrorContext(r.Context(), "failed to build direct issuer", "connector_id", connectorID, "err", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	srv.ServeHTTP(w, r)
}

// server returns the direct issuer of a connector, building it on first use.
func (d *directIssuers) server(connectorID string) (*Server, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if srv, ok := d.servers[connectorID]; ok {
		return srv, nil
	}
	srv, err := d.build(connectorID)
	if err != nil {
		return nil, err
	}
	if d.servers == nil {
		d.servers = make(map[string]*Server)
	}
	d.servers[connectorID] = srv
	return srv, nil
}
