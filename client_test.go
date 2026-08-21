package clientgo

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/FlashStart-Group/client-go/v8/authentication"
	"github.com/FlashStart-Group/client-go/v8/network"
	openapi_types "github.com/oapi-codegen/runtime/types"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestNewRejectsInvalidCredentials(t *testing.T) {
	tests := []Options{
		{},
		{APIKey: "key", AccessToken: "token"},
	}
	for _, options := range tests {
		if _, err := New(options); err == nil {
			t.Fatal("New() error = nil")
		}
	}
}

func TestAPIKeyAuthentication(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-API-Key"); got != "key" {
			t.Errorf("X-API-Key = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	defer server.Close()
	client, err := New(Options{APIKey: "key", NetworkBaseURL: server.URL, ProtectionBaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Network.ListNetworksWithResponse(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestBearerAuthentication(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer token" {
			t.Errorf("Authorization = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	defer server.Close()
	client, err := New(Options{AccessToken: "token", NetworkBaseURL: server.URL, ProtectionBaseURL: server.URL, IntegrationBaseURL: server.URL, ReportBaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Protection.ListPoliciesWithResponse(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err = client.Integration.GetPhysicalDevicesWithResponse(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err = client.Report.GetCustomersReportDashboardWithResponse(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticationClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/login" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client, err := New(Options{AccessToken: "token", AuthenticationBaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	username := openapi_types.Email("user@example.com")
	if _, err := client.Authentication.LoginWithResponse(context.Background(), authentication.LoginJSONRequestBody{Username: &username, Password: "password"}); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticationDefaultBaseURL(t *testing.T) {
	var scheme, host, path string
	client, err := New(Options{APIKey: "key", HTTPClient: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		scheme = request.URL.Scheme
		host = request.URL.Host
		path = request.URL.Path
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{}`)),
		}, nil
	})}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Authentication.LoginWithResponse(context.Background(), authentication.LoginJSONRequestBody{Password: "password"}); err != nil {
		t.Fatal(err)
	}
	if host != "core.flashstart.com" {
		t.Errorf("host = %q", host)
	}
	if scheme != "https" {
		t.Errorf("scheme = %q", scheme)
	}
	if path != "/authentication/v1/login" {
		t.Errorf("path = %q", path)
	}
}

func TestAuthenticationRefreshExpiryPrecision(t *testing.T) {
	const expiry int64 = 1786523456789
	response, err := authentication.ParseRefreshTokenResponse(&http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(`{
			"accessToken":"access",
			"accessTokenExpiresAt":1786523456789,
			"refreshToken":"refresh",
			"refreshTokenExpiresAt":1786523456789
		}`)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.JSON200 == nil {
		t.Fatal("JSON200 = nil")
	}
	if response.JSON200.AccessTokenExpiresAt != expiry {
		t.Errorf("AccessTokenExpiresAt = %d, want %d", response.JSON200.AccessTokenExpiresAt, expiry)
	}
	if response.JSON200.RefreshTokenExpiresAt != expiry {
		t.Errorf("RefreshTokenExpiresAt = %d, want %d", response.JSON200.RefreshTokenExpiresAt, expiry)
	}
}

func TestNullableNetworkPolicyDNS(t *testing.T) {
	response, err := network.ParseAddNetworkPolicyResponse(&http.Response{
		StatusCode: http.StatusCreated,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"dns":null}`)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.JSON201 == nil || response.JSON201.Dns != nil {
		t.Fatalf("Dns = %#v", response.JSON201)
	}
}
