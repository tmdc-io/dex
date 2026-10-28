package authflow

// direct.go holds the pieces of the flow specific to direct connector issuers:
// issuers pinned to a single connector (see Handler.Connector).
//
// Redirect connectors only accept the callback URL they are registered with,
// which lives on the primary issuer, so a login started on a direct issuer
// comes back through the primary issuer's callback. To hand the flow back to
// the issuer it started on, a direct issuer tags the state it gives the
// connector; the callback strips the tag and continues on the direct issuer.

import (
	"strings"

	"github.com/dexidp/dex/server/internal"
	"github.com/dexidp/dex/storage"
)

// directStateSuffix tags the connector state of a login started on a direct
// issuer. Auth request IDs are lowercase base32, so they never contain a dot.
const directStateSuffix = ".direct"

// connectorAllowed reports whether this issuer serves logins through connID.
func (h *Handler) connectorAllowed(connID string) bool {
	return h.Connector == "" || h.Connector == connID
}

// connectorState is the state (OAuth2 "state", SAML RelayState) handed to the
// connector, which it returns on the callback.
func (h *Handler) connectorState(authReq storage.AuthRequest) string {
	if h.Connector != "" {
		return authReq.ID + directStateSuffix
	}
	return authReq.ID
}

// parseConnectorState returns the auth request ID carried by a connector state
// and whether the login was started on a direct issuer.
func parseConnectorState(state string) (authID string, direct bool) {
	return strings.CutSuffix(state, directStateSuffix)
}

// callbackURL is the callback URL redirect connectors send the user back to.
func (h *Handler) callbackURL() string {
	if h.CallbackURL != "" {
		return h.CallbackURL
	}
	return h.IssuerURL.AbsURL("/callback")
}

// buildCallbackContinueURL is buildContinueURL for a connector callback: a login
// started on a direct issuer continues on that issuer, so the response (and any
// token minted with it) carries the issuer the client started the flow with.
func (h *Handler) buildCallbackContinueURL(authReq storage.AuthRequest, direct bool) string {
	if direct && h.Connector == "" && h.DirectIssuerURL != nil {
		issuerURL := h.DirectIssuerURL(authReq.ConnectorID)
		return internal.StepURL(issuerURL.AbsPath("/auth"), authReq, internal.StepContinue, nil)
	}
	return h.buildContinueURL(authReq)
}
