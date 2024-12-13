package aad_b2c

import (
	"context"
	"errors"
	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/Azure/go-autorest/logger"
)

type AzGraph struct {
	azr                autorest.Authorizer
	tenantId           string
	useragent          string
	securityGroupsOnly bool
	ctx                context.Context
}

func NewAzGraph(
	adEndpoint,
	tenantId,
	clientId,
	clientSecret,
	useragent string,
	securityGroupsOnly bool,
	ctx context.Context,
) (*AzGraph, error) {
	azr, err := getAuthorizerForResource(
		adEndpoint,
		tenantId,
		clientId,
		clientSecret,
		azure.PublicCloud.ResourceIdentifiers.Graph,
	)
	if err != nil {
		return nil, err
	}
	azg := AzGraph{
		azr:                azr,
		tenantId:           tenantId,
		useragent:          useragent,
		securityGroupsOnly: securityGroupsOnly,
		ctx:                ctx,
	}
	return &azg, nil
}

func (a AzGraph) GetUser(id string) (*graphrbac.User, error) {
	uc := graphrbac.NewUsersClient(a.tenantId)
	uc.Authorizer = a.azr
	if err := uc.AddToUserAgent(a.useragent); err != nil {
		return nil, err
	}
	u, err := uc.Get(a.ctx, id)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (a AzGraph) GetGroup(id string) (*graphrbac.ADGroup, error) {
	gc := graphrbac.NewGroupsClient(a.tenantId)
	gc.Authorizer = a.azr
	if err := gc.AddToUserAgent(a.useragent); err != nil {
		return nil, err
	}
	g, err := gc.Get(a.ctx, id)
	if err != nil {
		return nil, err
	}
	return &g, nil
}

func (a AzGraph) ListGroupsForUser(id string) (*graphrbac.UserGetMemberGroupsResult, error) {

	u, err := a.GetUser(id)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, err
	}
	uc := graphrbac.NewUsersClient(a.tenantId)
	uc.Authorizer = a.azr
	if err := uc.AddToUserAgent(a.useragent); err != nil {
		return nil, err
	}
	gl, err := uc.GetMemberGroups(a.ctx, id, graphrbac.UserGetMemberGroupsParameters{
		AdditionalProperties: nil,
		SecurityEnabledOnly:  &a.securityGroupsOnly,
	})
	if err != nil {
		return nil, err
	}
	return &gl, nil
}

func getAuthorizerForResource(
	adEndpoint,
	tenantId,
	clientId,
	clientSecret,
	resource string,
) (autorest.Authorizer, error) {
	config, err := getClientCredentials(adEndpoint, tenantId, clientId, clientSecret, resource)
	if err != nil {
		return nil, err
	}
	return config.Authorizer()
	//return auth.NewAuthorizerFromEnvironmentWithResource()

}

// TODO: medium - include additional configuration settings
func getClientCredentials(
	adEndpoint,
	tenantId,
	clientId,
	clientSecret,
	resource string,
) (auth.ClientCredentialsConfig, error) {
	if clientSecret == "" {
		logger.Instance.Writeln(logger.LogInfo, "EnvironmentSettings.GetClientCredentials() missing client secret")
		return auth.ClientCredentialsConfig{}, errors.New("missing client secret")
	}
	config := auth.NewClientCredentialsConfig(clientId, clientSecret, tenantId)
	config.AADEndpoint = adEndpoint
	config.Resource = resource
	return config, nil
}
