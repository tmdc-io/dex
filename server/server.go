package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/dexidp/dex/pkg/featureflags"
	"github.com/dexidp/dex/server/authflow"
	"github.com/dexidp/dex/server/backchannel"
	"github.com/dexidp/dex/server/connectors"
	"github.com/dexidp/dex/server/consent"
	"github.com/dexidp/dex/server/device"
	"github.com/dexidp/dex/server/discovery"
	"github.com/dexidp/dex/server/grants"
	"github.com/dexidp/dex/server/home"
	"github.com/dexidp/dex/server/introspection"
	"github.com/dexidp/dex/server/logout"
	"github.com/dexidp/dex/server/mfa"
	"github.com/dexidp/dex/server/oauth2"
	"github.com/dexidp/dex/server/router"
	"github.com/dexidp/dex/server/session"
	"github.com/dexidp/dex/server/templates"
	"github.com/dexidp/dex/server/tokens"
	"github.com/dexidp/dex/server/userinfo"
	"github.com/dexidp/dex/storage"
)

// Server is the top level object.
type Server struct {
	issuerURL oauth2.IssuerURL

	// In-memory cache of opened connectors.
	connectors *connectors.Cache

	storage storage.Storage

	mux http.Handler

	templates *templates.Templates

	logger *slog.Logger

	// issuer turns an Authorization into a TokenSet.
	issuer *tokens.Issuer

	// sessions owns the session cookie, SSO and auth-session CRUD. Built before the
	// issuer because the issuer reads it to resolve the "sid" claim.
	sessions *session.Manager

	// discovery is built once from config and shared by the mounted HTTP handler
	// and the gRPC API's Discovery accessor.
	discovery *discovery.Handler

	// backchannel notifies relying parties that a session ended. Shared with the
	// gRPC API, which ends sessions too.
	backchannel *backchannel.Notifier

	// direct serves the per-connector direct issuers. Nil when they are disabled,
	// and on a direct issuer itself.
	direct *directIssuers

	// connector pins a direct issuer to its connector; empty on the primary
	// issuer. callbackURL is then the primary issuer's connector callback.
	connector   string
	callbackURL string
}

// Connectors is the server's connector cache. The gRPC API needs it to
// invalidate the cache on connector CRUD.
func (s *Server) Connectors() *connectors.Cache { return s.connectors }

// Discovery is the handler that builds the OIDC discovery document. The gRPC
// API serves the same handler that is mounted for HTTP, so both return an
// identical document.
func (s *Server) Discovery() *discovery.Handler { return s.discovery }

// Backchannel notifies a session's relying parties that it has ended. The gRPC
// API terminates sessions as well, and an RP cannot tell — and has no reason to
// care — whether a session ended by logout or by an operator's hand.
func (s *Server) Backchannel() *backchannel.Notifier { return s.backchannel }

// NewServer constructs a server from the provided config.
func NewServer(ctx context.Context, c Config) (*Server, error) {
	return newServer(ctx, c)
}

func newServer(ctx context.Context, c Config) (*Server, error) {
	rc, err := normalizeConfig(&c)
	if err != nil {
		return nil, err
	}

	store := newKeyCacher(c.Storage, rc.now)
	s := assemble(c, rc, store, connectors.NewCache(store, connectors.Resolver(store, c.Logger, ConnectorsConfig)))

	if err := s.openConnectors(ctx, c); err != nil {
		return nil, err
	}

	if featureflags.SessionsEnabled.Enabled() {
		s.logger.InfoContext(ctx, "sessions feature flag is enabled")
	}

	instrument := instrumentHandler(c.PrometheusRegistry)
	r := mux.NewRouter().SkipClean(true).UseEncodedPath()
	r.NotFoundHandler = http.NotFoundHandler()
	if rc.directIssuerPath != "" {
		s.direct = &directIssuers{
			path:    rc.directIssuerPath,
			primary: s.issuerURL,
			storage: s.storage,
			logger:  s.logger,
			build: func(connectorID string) (*Server, error) {
				return s.newDirectIssuer(c, instrument, connectorID)
			},
		}
		r.PathPrefix(rc.directIssuerPath + "/").Handler(s.direct)
		s.logger.InfoContext(ctx, "direct connector issuers enabled", "path", rc.directIssuerPath)
	}
	s.mount(router.New(routerConfig(r, s.issuerURL, c, instrument)), c, rc)
	s.mux = r

	c.Signer.Start(ctx)
	s.startGarbageCollection(ctx, value(c.GCFrequency, 5*time.Minute), rc.now)

	return s, nil
}

// newDirectIssuer builds the direct issuer of a connector: a full issuer under
// the direct issuer path whose login flow is pinned to that connector. It shares
// the primary issuer's storage, signer, connector cache and metrics; the signer
// and garbage collection are run by the primary issuer alone.
func (s *Server) newDirectIssuer(c Config, instrument func(string, http.Handler) http.HandlerFunc, connectorID string) (*Server, error) {
	issuerURL := s.direct.issuerURL(connectorID)
	c.Issuer = issuerURL.String()
	c.DirectConnectorIssuers = false
	rc, err := normalizeConfig(&c)
	if err != nil {
		return nil, err
	}

	d := assemble(c, rc, s.storage, s.connectors)
	d.connector = connectorID
	// Connectors only accept the redirect URI they are registered with, which
	// is the primary issuer's callback.
	d.callbackURL = s.issuerURL.AbsURL("/callback")

	r := mux.NewRouter().SkipClean(true).UseEncodedPath()
	r.NotFoundHandler = http.NotFoundHandler()
	d.mount(router.New(routerConfig(r, d.issuerURL, c, instrument)), c, rc)
	d.mux = r
	return d, nil
}

// routerConfig is the router.Config of an issuer.
func routerConfig(r *mux.Router, issuerURL oauth2.IssuerURL, c Config, instrument func(string, http.Handler) http.HandlerFunc) router.Config {
	return router.Config{
		Router:       r,
		IssuerPath:   issuerURL.Path,
		Headers:      c.Headers,
		RealIPHeader: c.RealIPHeader,
		Instrument:   instrument,
		RealIP:       router.ParseRealIP(c.RealIPHeader, c.TrustedRealIPCIDRs),
		CORSOrigins:  c.AllowedOrigins,
		CORSHeaders:  c.AllowedHeaders,
	}
}

// assemble builds the issuer-specific parts of a server (sessions, token issuer,
// back-channel notifier, discovery) on top of the given storage and connector
// cache. It neither opens connectors nor mounts routes.
func assemble(c Config, rc resolvedConfig, store storage.Storage, conns *connectors.Cache) *Server {
	s := &Server{
		issuerURL:  rc.issuerURL,
		storage:    store,
		templates:  rc.templates,
		logger:     c.Logger,
		connectors: conns,
	}
	s.sessions = &session.Manager{
		Storage:   s.storage,
		Config:    c.SessionConfig,
		Now:       rc.now,
		Logger:    s.logger,
		IssuerURL: s.issuerURL,
	}
	s.issuer = tokens.NewIssuer(s.storage, c.Signer, s.issuerURL.URL, rc.idTokensValidFor, rc.now, s.logger)
	s.backchannel = &backchannel.Notifier{
		Storage:   s.storage,
		Signer:    c.Signer,
		IssuerURL: s.issuerURL,
		Logger:    s.logger,
		Now:       rc.now,
	}
	// Build the discovery handler once from config; both the mounted HTTP route
	// and the gRPC API (via Discovery) serve this same handler.
	s.discovery = &discovery.Handler{
		IssuerURL:       s.issuerURL,
		Templates:       s.templates,
		Signer:          c.Signer,
		Logger:          s.logger,
		ResponseTypes:   rc.responseTypes,
		GrantTypes:      rc.grantTypes,
		PKCEMethods:     c.PKCE.CodeChallengeMethodsSupported,
		SessionsEnabled: c.SessionConfig != nil,
	}
	return s
}

// openConnectors opens every connector in storage into the cache. Nothing is
// served without at least one, so an empty set is an error; so is a single
// failure, unless the server is configured to start on a subset.
func (s *Server) openConnectors(ctx context.Context, c Config) error {
	// This list includes the static connectors defined in the ConfigMap and
	// dynamic connectors retrieved from the storage.
	storageConnectors, err := c.Storage.ListConnectors(ctx)
	if err != nil {
		return fmt.Errorf("server: failed to list connector objects from storage: %v", err)
	}

	if len(storageConnectors) == 0 && s.connectors.Len() == 0 {
		return errors.New("server: no connectors specified")
	}

	var failedCount int
	for _, conn := range storageConnectors {
		if _, err := s.connectors.Open(conn); err != nil {
			failedCount++
			if c.ContinueOnConnectorFailure {
				s.logger.Error("server: Failed to open connector", "id", conn.ID, "err", err)
				continue
			}
			return fmt.Errorf("server: Failed to open connector %s: %v", conn.ID, err)
		}
	}

	if c.ContinueOnConnectorFailure && failedCount == len(storageConnectors) {
		return fmt.Errorf("server: failed to open all connectors (%d/%d)", failedCount, len(storageConnectors))
	}

	return nil
}

// instrumentHandler returns the per-route metrics wrapper the mux applies. With
// no registry it is the identity wrapper, so metrics stay opt-in.
func instrumentHandler(registry *prometheus.Registry) func(string, http.Handler) http.HandlerFunc {
	if registry == nil {
		return func(_ string, handler http.Handler) http.HandlerFunc { return handler.ServeHTTP }
	}

	requestCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Count of all HTTP requests.",
	}, []string{"code", "method", "handler"})

	durationHist := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "request_duration_seconds",
		Help:    "A histogram of latencies for requests.",
		Buckets: []float64{.25, .5, 1, 2.5, 5, 10},
	}, []string{"code", "method", "handler"})

	sizeHist := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "response_size_bytes",
		Help:    "A histogram of response sizes for requests.",
		Buckets: []float64{200, 500, 900, 1500},
	}, []string{"code", "method", "handler"})

	registry.MustRegister(requestCounter, durationHist, sizeHist)

	return func(handlerName string, handler http.Handler) http.HandlerFunc {
		return promhttp.InstrumentHandlerDuration(durationHist.MustCurryWith(prometheus.Labels{"handler": handlerName}),
			promhttp.InstrumentHandlerCounter(requestCounter.MustCurryWith(prometheus.Labels{"handler": handlerName}),
				promhttp.InstrumentHandlerResponseSize(sizeHist.MustCurryWith(prometheus.Labels{"handler": handlerName}), handler),
			),
		)
	}
}

// mount wires every domain onto routes. Self-contained domains mount their own
// routes through the router.Mux abstraction; this is the only place they are
// wired in.
func (s *Server) mount(routes router.Mux, c Config, rc resolvedConfig) {
	// sessions is shared infrastructure (session cookie, SSO, auth-session CRUD)
	// referenced by the flow steps mounted below. The steps themselves hold no
	// reference to one another; the /auth dispatcher decides MFA and consent from
	// persisted state and config, so mfa and consent are mounted inline like the
	// rest.
	sessions := s.sessions

	var directIssuerURL func(string) oauth2.IssuerURL
	if s.direct != nil {
		directIssuerURL = s.direct.issuerURL
	}

	for _, h := range []router.Handler{
		s.discovery,
		&grants.Handler{
			Issuer:              s.issuer,
			Storage:             s.storage,
			Connectors:          s.connectors,
			Now:                 rc.now,
			Logger:              s.logger,
			PasswordConnector:   c.PasswordConnector,
			RefreshPolicy:       c.RefreshTokenPolicy,
			Sessions:            sessions,
			SessionsEnabled:     c.SessionConfig != nil,
			SupportedGrantTypes: rc.grantTypes,
		},
		&userinfo.Handler{
			Issuer: s.issuerURL.String(),
			Signer: c.Signer,
			Logger: s.logger,
		},
		&introspection.Handler{
			Issuer:        s.issuerURL.String(),
			Signer:        c.Signer,
			Storage:       s.storage,
			Logger:        s.logger,
			RefreshPolicy: c.RefreshTokenPolicy,
			Sessions:      sessions,
		},
		&device.Handler{
			IssuerURL:        s.issuerURL,
			Storage:          s.storage,
			Templates:        s.templates,
			Now:              rc.now,
			RequestsValidFor: rc.deviceRequestsValidFor,
			Logger:           s.logger,
			Issuer:           s.issuer,
			Connectors:       s.connectors,
		},
		&home.Handler{
			IssuerURL: s.issuerURL,
			Storage:   s.storage,
			Templates: s.templates,
			Logger:    s.logger,
			Sessions:  sessions,
		},
		&authflow.Handler{
			IssuerURL:              s.issuerURL,
			Connectors:             s.connectors,
			Storage:                s.storage,
			Templates:              s.templates,
			Signer:                 c.Signer,
			Now:                    rc.now,
			Logger:                 s.logger,
			AlwaysShowLogin:        c.AlwaysShowLoginScreen,
			SupportedResponseTypes: rc.responseTypes,
			PKCE:                   c.PKCE,
			AuthRequestsValidFor:   rc.authRequestsValidFor,
			Sessions:               sessions,
			Issuer:                 s.issuer,
			MFAEnabled:             len(c.MFAProviders) > 0,
			DefaultMFAChain:        c.DefaultMFAChain,
			SkipApproval:           c.SkipApprovalScreen,
			Connector:              s.connector,
			CallbackURL:            s.callbackURL,
			DirectIssuerURL:        directIssuerURL,
		},
		&mfa.Handler{
			Storage:         s.storage,
			Templates:       s.templates,
			Logger:          s.logger,
			IssuerURL:       s.issuerURL,
			MFAProviders:    c.MFAProviders,
			DefaultMFAChain: c.DefaultMFAChain,
			Now:             rc.now,
			Connectors:      s.connectors,
		},
		&consent.Handler{
			Storage:      s.storage,
			Templates:    s.templates,
			Logger:       s.logger,
			IssuerURL:    s.issuerURL,
			Sessions:     sessions,
			SkipApproval: c.SkipApprovalScreen,
		},
		&logout.Handler{
			Storage:     s.storage,
			Templates:   s.templates,
			Logger:      s.logger,
			Sessions:    sessions,
			Connectors:  s.connectors,
			Issuer:      s.issuer,
			Signer:      c.Signer,
			IssuerURL:   s.issuerURL,
			Now:         rc.now,
			Backchannel: s.backchannel,
		},
	} {
		h.Mount(routes)
	}

	routes.Handle("/healthz", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !c.HealthChecker.IsHealthy() {
			s.renderError(r, w, http.StatusInternalServerError, "Health check failed.")
			return
		}
		fmt.Fprintf(w, "Health check passed")
	}))

	routes.HandlePrefix("/static", rc.static)
	routes.HandlePrefix("/theme", rc.theme)
	routes.HandleFunc("/robots.txt", rc.robots)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// newKeyCacher returns a storage which caches keys so long as the next
func newKeyCacher(s storage.Storage, now func() time.Time) storage.Storage {
	if now == nil {
		now = time.Now
	}
	return &keyCacher{Storage: s, now: now}
}

type keyCacher struct {
	storage.Storage

	now  func() time.Time
	keys atomic.Value // Always holds nil or type *storage.Keys.
}

func (k *keyCacher) GetKeys(ctx context.Context) (storage.Keys, error) {
	keys, ok := k.keys.Load().(*storage.Keys)
	if ok && keys != nil && k.now().Before(keys.NextRotation) {
		return *keys, nil
	}

	storageKeys, err := k.Storage.GetKeys(ctx)
	if err != nil {
		return storageKeys, err
	}

	if k.now().Before(storageKeys.NextRotation) {
		k.keys.Store(&storageKeys)
	}
	return storageKeys, nil
}

func (s *Server) startGarbageCollection(ctx context.Context, frequency time.Duration, now func() time.Time) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(frequency):
				if r, err := s.storage.GarbageCollect(ctx, now()); err != nil {
					s.logger.ErrorContext(ctx, "garbage collection failed", "err", err)
				} else if !r.IsEmpty() {
					s.logger.InfoContext(ctx, "garbage collection run, delete auth",
						"requests", r.AuthRequests, "auth_codes", r.AuthCodes,
						"device_requests", r.DeviceRequests, "device_tokens", r.DeviceTokens,
						"auth_sessions", r.AuthSessions)
				}
			}
		}
	}()
}

// renderError renders a user-facing error page for the non-flow endpoints the
// server still serves directly (e.g. /healthz).
func (s *Server) renderError(r *http.Request, w http.ResponseWriter, status int, description string) {
	templates.RenderError(s.templates, s.logger, r, w, status, description)
}
