package clientgo

import (
	"context"
	"errors"
	"net/http"

	"github.com/FlashStart-Group/client-go/v8/authentication"
	"github.com/FlashStart-Group/client-go/v8/integration"
	"github.com/FlashStart-Group/client-go/v8/network"
	"github.com/FlashStart-Group/client-go/v8/protection"
	"github.com/FlashStart-Group/client-go/v8/report"
)

const (
	defaultAuthenticationBaseURL = "https://core.flashstart.com/authentication"
	defaultIntegrationBaseURL    = "https://core.flashstart.com/integration"
	defaultNetworkBaseURL        = "https://core.flashstart.com/network"
	defaultProtectionBaseURL     = "https://core.flashstart.com/protection"
	defaultReportBaseURL         = "https://core.flashstart.com/report"
)

type Options struct {
	APIKey                string
	AccessToken           string
	AuthenticationBaseURL string
	IntegrationBaseURL    string
	NetworkBaseURL        string
	ProtectionBaseURL     string
	ReportBaseURL         string
	HTTPClient            *http.Client
}

type Client struct {
	Authentication *authentication.ClientWithResponses
	Integration    *integration.ClientWithResponses
	Network        *network.ClientWithResponses
	Protection     *protection.ClientWithResponses
	Report         *report.ClientWithResponses
}

func New(options Options) (*Client, error) {
	if (options.APIKey == "") == (options.AccessToken == "") {
		return nil, errors.New("provide exactly one of APIKey or AccessToken")
	}
	if options.AuthenticationBaseURL == "" {
		options.AuthenticationBaseURL = defaultAuthenticationBaseURL
	}
	if options.IntegrationBaseURL == "" {
		options.IntegrationBaseURL = defaultIntegrationBaseURL
	}
	if options.NetworkBaseURL == "" {
		options.NetworkBaseURL = defaultNetworkBaseURL
	}
	if options.ProtectionBaseURL == "" {
		options.ProtectionBaseURL = defaultProtectionBaseURL
	}
	if options.ReportBaseURL == "" {
		options.ReportBaseURL = defaultReportBaseURL
	}
	if options.HTTPClient == nil {
		options.HTTPClient = http.DefaultClient
	}
	auth := func(_ context.Context, request *http.Request) error {
		if options.APIKey != "" {
			request.Header.Set("X-API-Key", options.APIKey)
		} else {
			request.Header.Set("Authorization", "Bearer "+options.AccessToken)
		}
		return nil
	}
	authenticationClient, err := authentication.NewClientWithResponses(options.AuthenticationBaseURL, authentication.WithHTTPClient(options.HTTPClient), authentication.WithRequestEditorFn(auth))
	if err != nil {
		return nil, err
	}
	integrationClient, err := integration.NewClientWithResponses(options.IntegrationBaseURL, integration.WithHTTPClient(options.HTTPClient), integration.WithRequestEditorFn(auth))
	if err != nil {
		return nil, err
	}
	networkClient, err := network.NewClientWithResponses(options.NetworkBaseURL, network.WithHTTPClient(options.HTTPClient), network.WithRequestEditorFn(auth))
	if err != nil {
		return nil, err
	}
	protectionClient, err := protection.NewClientWithResponses(options.ProtectionBaseURL, protection.WithHTTPClient(options.HTTPClient), protection.WithRequestEditorFn(auth))
	if err != nil {
		return nil, err
	}
	reportClient, err := report.NewClientWithResponses(options.ReportBaseURL, report.WithHTTPClient(options.HTTPClient), report.WithRequestEditorFn(auth))
	if err != nil {
		return nil, err
	}
	return &Client{Authentication: authenticationClient, Integration: integrationClient, Network: networkClient, Protection: protectionClient, Report: reportClient}, nil
}
