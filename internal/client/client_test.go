package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

type fakeAPI struct {
	*httptest.Server
	tokenCalls atomic.Int32
	throttled  atomic.Bool
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	f := &fakeAPI{}
	mux := http.NewServeMux()

	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		f.tokenCalls.Add(1)
		_ = r.ParseForm()
		want := map[string]string{
			"grant_type":    "client_credentials",
			"client_id":     "cid",
			"client_secret": "secret",
			"organization":  "org_test",
			"audience":      f.URL + "/management/api",
		}
		for k, v := range want {
			if got := r.PostForm.Get(k); got != v {
				t.Errorf("token request %s = %q, want %q", k, got, v)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":900}`))
	})

	mux.HandleFunc("GET /api/management/v1/governance/policies", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.Header.Get("User-Agent"); got != "test-agent" {
			t.Errorf("User-Agent = %q", got)
		}
		if !f.throttled.Swap(true) {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		page := GovernancePolicyList{Data: []GovernancePolicySummary{{PolicyId: uuid.New(), Title: "two"}}}
		if r.URL.Query().Get("cursor") == "" {
			next := "page2"
			page = GovernancePolicyList{
				Data:       []GovernancePolicySummary{{PolicyId: uuid.New(), Title: "one"}},
				HasNext:    true,
				NextCursor: &next,
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(page)
	})

	mux.HandleFunc("GET /api/management/v1/governance/policies/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"type":"about:blank","title":"Not Found","status":404,"code":"policy_not_found","request_id":"req-1"}`))
	})

	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func newTestClient(t *testing.T, f *fakeAPI) *Manifold {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	m, err := New(ctx, Config{
		Endpoint:     f.URL,
		TokenURL:     f.URL + "/oauth/token",
		ClientID:     "cid",
		ClientSecret: "secret",
		Organization: "org_test",
		UserAgent:    "test-agent",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

func TestListAllGovernancePolicies(t *testing.T) {
	f := newFakeAPI(t)
	m := newTestClient(t, f)

	// The construction context is cancelled by now; the token source must not depend on it.
	got, err := m.ListAllGovernancePolicies(t.Context(), ListGovernancePoliciesParams{})
	if err != nil {
		t.Fatalf("ListAllGovernancePolicies: %v", err)
	}
	if len(got) != 2 || got[0].Title != "one" || got[1].Title != "two" {
		t.Fatalf("unexpected pages: %+v", got)
	}
	if n := f.tokenCalls.Load(); n != 1 {
		t.Errorf("token minted %d times, want 1", n)
	}
}

func TestGetGovernancePolicyNotFound(t *testing.T) {
	f := newFakeAPI(t)
	m := newTestClient(t, f)

	r, err := m.GetGovernancePolicyWithResponse(t.Context(), uuid.New())
	if err != nil {
		t.Fatalf("GetGovernancePolicy: %v", err)
	}
	apiErr := NewAPIError(r.StatusCode(), r.Body)
	if !IsNotFound(apiErr) {
		t.Fatalf("IsNotFound(%v) = false", apiErr)
	}
	if want := "management API returned HTTP 404: Not Found (request_id req-1)"; apiErr.Error() != want {
		t.Errorf("Error() = %q, want %q", apiErr.Error(), want)
	}
}

func TestNewRejectsRelativeEndpoint(t *testing.T) {
	if _, err := New(t.Context(), Config{Endpoint: "acme.app.manifoldsecurity.io"}); err == nil {
		t.Fatal("expected an error for an endpoint without a scheme")
	}
}
