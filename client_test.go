package clientgo

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/FlashStart-Group/client-go/v8/network"
)

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
	client, err := New(Options{AccessToken: "token", NetworkBaseURL: server.URL, ProtectionBaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Protection.ListPoliciesWithResponse(context.Background(), nil); err != nil {
		t.Fatal(err)
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
