package google

import (
	"context"
	"strings"

	"github.com/GoogleCloudPlatform/docker-credential-gcr/config"
	"github.com/GoogleCloudPlatform/docker-credential-gcr/credhelper"
	"github.com/GoogleCloudPlatform/docker-credential-gcr/store"
	"github.com/aquasecurity/trivy/pkg/fanal/image/registry/intf"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type GoogleRegistryClient struct {
	Store  store.GCRCredStore
	domain string
}

type Registry struct {
}

// Google container registry
const gcrURL = "gcr.io"

// Google artifact registry
const garURL = "docker.pkg.dev"

func (g *Registry) CheckOptions(domain string, option types.RegistryOptions) (intf.RegistryClient, error) {
	if !strings.HasSuffix(domain, gcrURL) && !strings.HasSuffix(domain, garURL) {
		return nil, xerrors.Errorf("Google registry: %w", types.InvalidURLPattern)
	}
	client := GoogleRegistryClient{domain: domain}
	if option.GCPCredPath != "" {
		client.Store = store.NewGCRCredStore(option.GCPCredPath)
	}
	return &client, nil
}

func (g *GoogleRegistryClient) GetCredential(_ context.Context) (username, password string, err error) {
	var credStore store.GCRCredStore
	if g.Store == nil {
		credStore, err = store.DefaultGCRCredStore()
		if err != nil {
			return "", "", xerrors.Errorf("failed to get GCRCredStore: %w", err)
		}
	} else {
		credStore = g.Store
	}
	userCfg, err := config.LoadUserConfig()
	if err != nil {
		return "", "", xerrors.Errorf("failed to load user config: %w", err)
	}
	helper := credhelper.NewGCRCredentialHelper(credStore, userCfg)
	return helper.Get(g.domain)
}
