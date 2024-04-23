package azure

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/preview/preview/containerregistry/runtime/containerregistry"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/aquasecurity/trivy/pkg/fanal/image/registry/intf"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type RegistryClient struct {
	domain string
}

type Registry struct {
}

const (
	azureURL = "azurecr.io"
	scope    = "https://management.azure.com/.default"
	scheme   = "https"
)

func (r *Registry) CheckOptions(domain string, _ types.RegistryOptions) (intf.RegistryClient, error) {
	if !strings.HasSuffix(domain, azureURL) {
		return nil, xerrors.Errorf("Azure registry: %w", types.InvalidURLPattern)
	}
	return &RegistryClient{domain: domain}, nil
}

func (r *RegistryClient) GetCredential(ctx context.Context) (string, string, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return "", "", xerrors.Errorf("unable to generate acr credential error: %w", err)
	}
	aadToken, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{scope}})
	if err != nil {
		return "", "", xerrors.Errorf("unable to get an access token: %w", err)
	}
	rt, err := refreshToken(ctx, aadToken.Token, r.domain)
	if err != nil {
		return "", "", xerrors.Errorf("unable to refresh token: %w", err)
	}
	return "00000000-0000-0000-0000-000000000000", *rt.RefreshToken, err
}

func refreshToken(ctx context.Context, accessToken, domain string) (containerregistry.RefreshToken, error) {
	tenantID := os.Getenv("AZURE_TENANT_ID")
	if tenantID == "" {
		return containerregistry.RefreshToken{}, errors.New("missing environment variable AZURE_TENANT_ID")
	}
	repoClient := containerregistry.NewRefreshTokensClient(fmt.Sprintf("%s://%s", scheme, domain))
	return repoClient.GetFromExchange(ctx, "access_token", domain, tenantID, "", accessToken)
}
