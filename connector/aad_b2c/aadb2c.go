// Package aad_b2c provides authentication strategies using Azure AD B2C.
package aad_b2c

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"net/http"
	"time"

	"golang.org/x/oauth2"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
)

// GroupNameFormat represents the format of the group identifier
// we use type of string instead of int because it's easier to
// marshall/unmarshall
type GroupNameFormat string

// Possible values for GroupNameFormat
const (
	GroupID   GroupNameFormat = "id"
	GroupName GroupNameFormat = "name"
)

const (
	// B2C
	scopeOpenid = "openid"
	// Microsoft requires this scope to return a refresh token
	// see https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-permissions-and-consent#offline_access
	scopeOfflineAccess = "offline_access"
)

//TODO: medium - create configurations for GovCloud override of default URLs

// Config holds configuration options for microsoft logins.
type Config struct {
	ClientID             string          `json:"clientID"`
	ClientSecret         string          `json:"clientSecret"`
	RedirectURI          string          `json:"redirectURI"`
	Tenant               string          `json:"tenant"`
	OnlySecurityGroups   bool            `json:"onlySecurityGroups"`
	Groups               []string        `json:"groups"`
	GroupNameFormat      GroupNameFormat `json:"groupNameFormat"`
	UseGroupsAsWhitelist bool            `json:"useGroupsAsWhitelist"`
	EmailToLowercase     bool            `json:"emailToLowercase"`
	Policy               string          `json:"policy"`
	TenantId             string          `json:"tenantId"`

	// PromptType is used for the prompt query parameter.
	// For valid values, see https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow#request-an-authorization-code.
	PromptType string `json:"promptType"`
}

// Open returns a strategy for logging in through Microsoft.
func (c *Config) Open(id string, logger log.Logger) (connector.Connector, error) {
	ctx := context.Background()
	azg, err := NewAzGraph(
		"https://login.microsoftonline.com",
		c.TenantId,
		c.ClientID,
		c.ClientSecret,
		"dex/2.37.0-d4",
		c.OnlySecurityGroups,
		ctx,
	)
	if err != nil {
		return nil, err
	}
	issuer := "https://" + c.TenantId + ".b2clogin.com/" + c.TenantId + ".onmicrosoft.com/" + c.Policy + "/v2.0/"
	logger.Infof("azure-ad-b2c: issuer - %s", issuer)
	ctx = oidc.InsecureIssuerURLContext(ctx, issuer)
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider: %v", err)
	}
	m := microsoftAADB2CConnector{
		provider: provider,
		verifier: provider.Verifier(
			&oidc.Config{
				ClientID:        c.ClientID,
				SkipIssuerCheck: true,
			},
		),
		graphURL:             "https://graph.microsoft.com",
		redirectURI:          c.RedirectURI,
		clientID:             c.ClientID,
		clientSecret:         c.ClientSecret,
		tenant:               c.Tenant,
		onlySecurityGroups:   c.OnlySecurityGroups,
		groups:               c.Groups,
		groupNameFormat:      c.GroupNameFormat,
		useGroupsAsWhitelist: c.UseGroupsAsWhitelist,
		logger:               logger,
		emailToLowercase:     c.EmailToLowercase,
		promptType:           c.PromptType,
		policy:               c.Policy,
		azg:                  azg,
	}

	// Azure AD B2C requires tenant and policy names
	if m.tenant == "" {
		return nil, fmt.Errorf("invalid connector config: tenant is required for Azure AD B2C")
	}
	if m.policy == "" {
		return nil, fmt.Errorf("invalid connector config: policy is required for Azure AD B2C")
	}

	// By default, use group names
	switch m.groupNameFormat {
	case "":
		m.groupNameFormat = GroupName
	case GroupID, GroupName:
	default:
		return nil, fmt.Errorf("invalid groupNameFormat: %s", m.groupNameFormat)
	}
	return &m, nil
}

type connectorData struct {
	AccessToken  string    `json:"accessToken"`
	RefreshToken string    `json:"refreshToken"`
	Expiry       time.Time `json:"expiry"`
}

var (
	_ connector.CallbackConnector = (*microsoftAADB2CConnector)(nil)
	_ connector.RefreshConnector  = (*microsoftAADB2CConnector)(nil)
)

type microsoftAADB2CConnector struct {
	provider             *oidc.Provider
	verifier             *oidc.IDTokenVerifier
	apiURL               string
	graphURL             string
	redirectURI          string
	clientID             string
	clientSecret         string
	tenant               string
	onlySecurityGroups   bool
	groupNameFormat      GroupNameFormat
	groups               []string
	useGroupsAsWhitelist bool
	logger               log.Logger
	emailToLowercase     bool
	promptType           string
	policy               string
	azg                  *AzGraph
}

func (c *microsoftAADB2CConnector) isOrgTenant() bool {
	return c.tenant != "common" && c.tenant != "consumers" && c.tenant != "organizations"
}

func (c *microsoftAADB2CConnector) groupsRequired(groupScope bool) bool {
	return (len(c.groups) > 0 || groupScope) && c.isOrgTenant()
}

func (c *microsoftAADB2CConnector) oauth2Config(scopes connector.Scopes) *oauth2.Config {
	microsoftScopes := []string{
		scopeOpenid,
		c.clientID,
	}

	if scopes.OfflineAccess {
		microsoftScopes = append(microsoftScopes, scopeOfflineAccess)
	}

	microsoftScopes = uniqueStringSlice(microsoftScopes)

	// https://docs.microsoft.com/en-us/azure/active-directory-b2c/b2clogin
	// https://tmdc0dataos0app.b2clogin.com/tmdc0dataos0app.onmicrosoft.com/b2c_1_default_signup_03_2022/oauth2/v2.0/authorize
	endpoint := oauth2.Endpoint{
		AuthURL:  "https://" + c.tenant + ".b2clogin.com/" + c.tenant + ".onmicrosoft.com/" + c.policy + "/oauth2/v2.0/authorize",
		TokenURL: "https://" + c.tenant + ".b2clogin.com/" + c.tenant + ".onmicrosoft.com/" + c.policy + "/oauth2/v2.0/token",
	}

	return &oauth2.Config{
		ClientID:     c.clientID,
		ClientSecret: c.clientSecret,
		Endpoint:     endpoint,
		Scopes:       microsoftScopes,
		RedirectURL:  c.redirectURI,
	}
}

func uniqueStringSlice(slice []string) []string {
	keys := make(map[string]bool)
	var list []string
	for _, entry := range slice {
		key := entry
		if _, value := keys[key]; !value {
			keys[key] = true
			list = append(list, entry)
		}
	}
	return list
}

func (c *microsoftAADB2CConnector) LoginURL(scopes connector.Scopes, callbackURL, state string) (string, error) {
	if c.redirectURI != callbackURL {
		return "", fmt.Errorf("expected callback URL %q did not match the URL in the config %q", callbackURL, c.redirectURI)
	}
	var options []oauth2.AuthCodeOption
	if c.promptType != "" {
		options = append(options, oauth2.SetAuthURLParam("prompt", c.promptType))
	}

	return c.oauth2Config(scopes).AuthCodeURL(state, options...), nil
}

func (c *microsoftAADB2CConnector) HandleCallback(s connector.Scopes, r *http.Request) (identity connector.Identity, err error) {
	q := r.URL.Query()
	if errType := q.Get("error"); errType != "" {
		return identity, &oauth2Error{errType, q.Get("error_description")}
	}

	oauth2Config := c.oauth2Config(s)

	token, err := oauth2Config.Exchange(r.Context(), q.Get("code"))
	if err != nil {
		return identity, fmt.Errorf("azure-ad-b2c: failed to get token: %v", err)
	}
	objectId := ""
	identity, objectId, err = c.createIdentity(r.Context(), identity, token)
	if err != nil {
		return identity, fmt.Errorf("azure-ad-b2c: failed to get token: %v", err)
	}

	if c.groupsRequired(s.Groups) {
		g, err := c.azg.ListGroupsForUser(objectId)
		if err != nil {
			return identity, fmt.Errorf("azure-ad-b2c: get groups: %v", err)
		}

		if g == nil || g.Value == nil {
			return identity, fmt.Errorf("azure-ad-b2c: get groups: failure retrieving groups for object id: %s", objectId)
		}

		var groupNames []string
		var groupIds []string
		for _, gn := range *g.Value {
			group, err := c.azg.GetGroup(gn)
			if err != nil {
				c.logger.Warnf("azure-ad-b2c: failure getting group %s, continuing: %s", gn, err.Error())
				continue
			}
			if group == nil {
				continue
			}
			if group.DisplayName != nil {
				groupNames = append(groupNames, *group.DisplayName)
			}
			if group.ObjectID != nil {
				groupIds = append(groupIds, *group.ObjectID)
			}
		}

		switch c.groupNameFormat {
		case GroupName:
			{
				identity.Groups = groupNames
			}
		case GroupID:
			{
				identity.Groups = groupIds
			}
		}

	}

	if s.OfflineAccess {
		data := connectorData{
			AccessToken:  token.AccessToken,
			RefreshToken: token.RefreshToken,
			Expiry:       token.Expiry,
		}
		connData, err := json.Marshal(data)
		if err != nil {
			return identity, fmt.Errorf("azure-ad-b2c: marshal connector data: %v", err)
		}
		identity.ConnectorData = connData
	}

	return identity, nil
}

func (c *microsoftAADB2CConnector) createIdentity(
	ctx context.Context,
	identity connector.Identity,
	token *oauth2.Token,
) (connector.Identity, string, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return identity, "", errors.New("azure-ad-b2c: no id_token in token response")
	}

	idToken, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return identity, "", fmt.Errorf("azure-ad-b2c: failed to verify ID Token: %v", err)
	}

	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return identity, "", fmt.Errorf("azure-ad-b2c: failed to decode claims: %v", err)
	}

	// We immediately want to run getUserInfo if configured before we validate the claims
	userInfo, err := c.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil {
		return identity, "", fmt.Errorf("azure-ad-b2c: error loading userinfo: %v", err)
	}
	if err := userInfo.Claims(&claims); err != nil {
		return identity, "", fmt.Errorf("azure-ad-b2c: failed to decode userinfo claims: %v", err)
	}

	userNameKey := "displayName"
	name, found := claims[userNameKey].(string)
	if !found {
		return identity, "", fmt.Errorf("azure-ad-b2c: missing \"userName\" claim, not found \"%s\" key", userNameKey)
	}

	userIdKey := "signInName"
	userId, found := claims[userIdKey].(string)
	if !found {
		return identity, "", fmt.Errorf("azure-ad-b2c: missing \"userId\" claim, not found \"%s\" key", userIdKey)
	}

	var email string
	emailKey := "email"
	email, found = claims[emailKey].(string)
	if !found {
		return identity, "", fmt.Errorf("azure-ad-b2c: missing \"email\" claim, not found \"%s\" key", emailKey)
	}

	objIdKey := "objectId"
	objectId, found := claims[objIdKey].(string)
	if !found {
		return identity, "", fmt.Errorf("azure-ad-b2c: missing \"objectId\" claim, not found \"%s\" key", objIdKey)
	}

	identity = connector.Identity{
		UserID:        userId,
		Username:      name,
		Email:         email,
		EmailVerified: true,
	}

	return identity, objectId, nil
}

// Refresh is used to refresh a session with the refresh token provided by the IdP
func (c *microsoftAADB2CConnector) Refresh(ctx context.Context, s connector.Scopes, identity connector.Identity) (connector.Identity, error) {
	cd := connectorData{}
	err := json.Unmarshal(identity.ConnectorData, &cd)
	if err != nil {
		return identity, fmt.Errorf("azure-ad-b2c: failed to unmarshal connector data: %v", err)
	}
	t := &oauth2.Token{
		RefreshToken: cd.RefreshToken,
		Expiry:       time.Now().Add(-time.Hour),
	}
	token, err := c.oauth2Config(s).TokenSource(ctx, t).Token()
	if err != nil {
		return identity, fmt.Errorf("azure-ad-b2c: failed to get refresh token: %v", err)
	}
	//objectId := ""
	identity, _, err = c.createIdentity(ctx, identity, token)
	return identity, err
}

type oauth2Error struct {
	error            string
	errorDescription string
}

func (e *oauth2Error) Error() string {
	if e.errorDescription == "" {
		return e.error
	}
	return e.error + ": " + e.errorDescription
}
