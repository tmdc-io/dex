package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/storage"
)

const (
	directTestClientID     = "direct-client"
	directTestClientSecret = "secret"
	directTestRedirectURI  = "https://client.example.com/callback"
)

// newDirectTestServer serves two mock connectors under issuer "( host )/dex",
// with direct connector issuers enabled unless updateConfig says otherwise.
func newDirectTestServer(t *testing.T, updateConfig func(c *Config)) (*httptest.Server, *Server) {
	t.Helper()
	httpServer, s := newTestServerWith(t, []storage.Connector{mockConnector("mock"), mockConnector("mock2")}, func(c *Config) {
		c.Issuer += "/dex"
		c.DirectConnectorIssuers = true
		if updateConfig != nil {
			updateConfig(c)
		}
	})
	t.Cleanup(httpServer.Close)

	require.NoError(t, s.storage.CreateClient(t.Context(), storage.Client{
		ID:           directTestClientID,
		Secret:       directTestClientSecret,
		RedirectURIs: []string{directTestRedirectURI},
	}))
	return httpServer, s
}

func directAuthQuery() string {
	return url.Values{
		"client_id":     {directTestClientID},
		"redirect_uri":  {directTestRedirectURI},
		"response_type": {"code"},
		"scope":         {"openid"},
		"state":         {"client-state"},
	}.Encode()
}

func serve(s *Server, method, target string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(method, target, nil))
	return rr
}

// followToClient follows every redirect from target until the flow lands on the
// client redirect URI, recording the path of each hop.
func followToClient(t *testing.T, s *Server, target string) (*url.URL, []string) {
	t.Helper()
	var hops []string
	for range 10 {
		rr := serve(s, http.MethodGet, target)
		require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, rr.Code, "GET %s: %s", target, rr.Body.String())
		loc, err := url.Parse(rr.Header().Get("Location"))
		require.NoError(t, err)
		if strings.HasPrefix(loc.String(), directTestRedirectURI) {
			return loc, hops
		}
		hops = append(hops, loc.Path)
		target = loc.String()
	}
	t.Fatal("flow did not reach the client redirect URI")
	return nil, nil
}

func idTokenIssuer(t *testing.T, idToken string) string {
	t.Helper()
	parts := strings.Split(idToken, ".")
	require.Len(t, parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims struct {
		Issuer string `json:"iss"`
	}
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims.Issuer
}

func TestDirectConnectorIssuerLogin(t *testing.T) {
	httpServer, s := newDirectTestServer(t, nil)
	directIssuer := httpServer.URL + "-direct/mock2"
	require.Equal(t, directIssuer, s.direct.issuerURL("mock2").AbsURL())

	clientRedirect, hops := followToClient(t, s, directIssuer+"/auth?"+directAuthQuery())

	// The flow goes straight to the pinned connector, comes back through the
	// primary issuer's callback, and is handed back to the direct issuer.
	require.Equal(t, []string{
		"/dex-direct/mock2/auth/mock2",
		"/dex/callback",
		"/dex-direct/mock2/auth",
	}, hops)
	require.Equal(t, "client-state", clientRedirect.Query().Get("state"))
	code := clientRedirect.Query().Get("code")
	require.NotEmpty(t, code)

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {directTestRedirectURI},
	}
	req := httptest.NewRequest(http.MethodPost, directIssuer+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(directTestClientID, directTestClientSecret)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	var tokenResp struct {
		IDToken string `json:"id_token"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &tokenResp))
	require.Equal(t, directIssuer, idTokenIssuer(t, tokenResp.IDToken))
}

func TestDirectConnectorIssuerSkipsSelectionScreen(t *testing.T) {
	httpServer, s := newDirectTestServer(t, func(c *Config) {
		c.AlwaysShowLoginScreen = true
	})

	// The primary issuer keeps the connector selection screen.
	rr := serve(s, http.MethodGet, httpServer.URL+"/auth?"+directAuthQuery())
	require.Equal(t, http.StatusOK, rr.Code)

	// The direct issuer goes straight to its connector.
	rr = serve(s, http.MethodGet, httpServer.URL+"-direct/mock/auth?"+directAuthQuery())
	require.Equal(t, http.StatusFound, rr.Code)
	loc, err := url.Parse(rr.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/dex-direct/mock/auth/mock", loc.Path)
}

func TestDirectConnectorIssuerRejectsOtherConnectors(t *testing.T) {
	httpServer, s := newDirectTestServer(t, nil)
	direct := httpServer.URL + "-direct/mock2"

	rr := serve(s, http.MethodGet, direct+"/auth?connector_id=mock&"+directAuthQuery())
	require.Equal(t, http.StatusBadRequest, rr.Code)

	rr = serve(s, http.MethodGet, direct+"/auth/mock?"+directAuthQuery())
	require.Equal(t, http.StatusNotFound, rr.Code)
}

func TestDirectConnectorIssuerDiscovery(t *testing.T) {
	httpServer, s := newDirectTestServer(t, nil)
	direct := httpServer.URL + "-direct/mock2"

	rr := serve(s, http.MethodGet, direct+"/.well-known/openid-configuration")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var doc struct {
		Issuer   string `json:"issuer"`
		AuthURL  string `json:"authorization_endpoint"`
		TokenURL string `json:"token_endpoint"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &doc))
	require.Equal(t, direct, doc.Issuer)
	require.Equal(t, direct+"/auth", doc.AuthURL)
	require.Equal(t, direct+"/token", doc.TokenURL)

	// The primary issuer is unchanged.
	rr = serve(s, http.MethodGet, httpServer.URL+"/.well-known/openid-configuration")
	require.Equal(t, http.StatusOK, rr.Code)
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &doc))
	require.Equal(t, httpServer.URL, doc.Issuer)
}

func TestDirectConnectorIssuerUnknownConnector(t *testing.T) {
	httpServer, s := newDirectTestServer(t, nil)

	for _, p := range []string{"-direct/unknown/auth", "-direct//auth", "-direct/../auth"} {
		rr := serve(s, http.MethodGet, httpServer.URL+p+"?"+directAuthQuery())
		require.Equal(t, http.StatusNotFound, rr.Code, p)
	}
}

func TestDirectConnectorIssuerDisabled(t *testing.T) {
	httpServer, s := newDirectTestServer(t, func(c *Config) {
		c.DirectConnectorIssuers = false
	})
	require.Nil(t, s.direct)

	rr := serve(s, http.MethodGet, httpServer.URL+"-direct/mock/.well-known/openid-configuration")
	require.Equal(t, http.StatusNotFound, rr.Code)
}

func TestDirectConnectorIssuerCustomPath(t *testing.T) {
	httpServer, s := newDirectTestServer(t, func(c *Config) {
		c.DirectConnectorIssuerPath = "/oidc-direct/"
	})
	u, err := url.Parse(httpServer.URL)
	require.NoError(t, err)
	origin := u.Scheme + "://" + u.Host

	rr := serve(s, http.MethodGet, origin+"/oidc-direct/mock/.well-known/openid-configuration")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.Equal(t, origin+"/oidc-direct/mock", s.direct.issuerURL("mock").AbsURL())
}

func TestDirectConnectorIssuerPath(t *testing.T) {
	tests := []struct {
		name       string
		issuerPath string
		configured string
		want       string
		wantErr    bool
	}{
		{name: "default", issuerPath: "/dex", want: "/dex-direct"},
		{name: "default trailing slash", issuerPath: "/dex/", want: "/dex-direct"},
		{name: "default root issuer", issuerPath: "", want: "/direct"},
		{name: "configured", issuerPath: "/oidc", configured: "/oidc-direct", want: "/oidc-direct"},
		{name: "configured is cleaned", issuerPath: "/oidc", configured: "/oidc-direct/", want: "/oidc-direct"},
		{name: "relative", issuerPath: "/oidc", configured: "oidc-direct", wantErr: true},
		{name: "same as issuer", issuerPath: "/oidc", configured: "/oidc/", wantErr: true},
		{name: "root", issuerPath: "/oidc", configured: "/", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := directConnectorIssuerPath(&Config{
				DirectConnectorIssuers:    true,
				DirectConnectorIssuerPath: tc.configured,
			}, tc.issuerPath)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}

	got, err := directConnectorIssuerPath(&Config{DirectConnectorIssuerPath: "/x"}, "/dex")
	require.NoError(t, err)
	require.Empty(t, got, "disabled")
}
