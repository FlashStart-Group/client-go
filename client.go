package clientgo

import (
	"context"
	"errors"
	"net/http"

	"github.com/FlashStart-Group/client-go/v8/network"
	"github.com/FlashStart-Group/client-go/v8/protection"
)

const (
	defaultNetworkBaseURL    = "https://core.flashstart.com/network"
	defaultProtectionBaseURL = "https://core.flashstart.com/protection"
)

type Options struct {
	APIKey            string
	AccessToken       string
	NetworkBaseURL    string
	ProtectionBaseURL string
	HTTPClient        *http.Client
}

type Client struct {
	Network    *network.ClientWithResponses
	Protection *protection.ClientWithResponses
}

func New(options Options) (*Client, error) {
	if (options.APIKey == "") == (options.AccessToken == "") {
		return nil, errors.New("provide exactly one of APIKey or AccessToken")
	}
	if options.NetworkBaseURL == "" {
		options.NetworkBaseURL = defaultNetworkBaseURL
	}
	if options.ProtectionBaseURL == "" {
		options.ProtectionBaseURL = defaultProtectionBaseURL
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
	networkClient, err := network.NewClientWithResponses(options.NetworkBaseURL, network.WithHTTPClient(options.HTTPClient), network.WithRequestEditorFn(auth))
	if err != nil {
		return nil, err
	}
	protectionClient, err := protection.NewClientWithResponses(options.ProtectionBaseURL, protection.WithHTTPClient(options.HTTPClient), protection.WithRequestEditorFn(auth))
	if err != nil {
		return nil, err
	}
	return &Client{Network: networkClient, Protection: protectionClient}, nil
}
