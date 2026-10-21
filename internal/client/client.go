package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-retryablehttp"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

const (
	apiBasePath  = "/api/management/v1"
	audiencePath = "/management/api"
	maxPageSize  = 250
)

type Config struct {
	// Endpoint is the instance root, e.g. https://acme.app.manifoldsecurity.io.
	Endpoint     string
	TokenURL     string
	ClientID     string
	ClientSecret string
	Organization string
	UserAgent    string
}

type Manifold struct {
	*ClientWithResponses
}

func New(ctx context.Context, cfg Config) (*Manifold, error) {
	endpoint, err := url.Parse(strings.TrimRight(cfg.Endpoint, "/"))
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" {
		return nil, fmt.Errorf("endpoint %q must be an absolute URL such as https://acme.app.manifoldsecurity.io", cfg.Endpoint)
	}

	cc := clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		TokenURL:     cfg.TokenURL,
		EndpointParams: url.Values{
			"audience":     {endpoint.String() + audiencePath},
			"organization": {cfg.Organization},
		},
		AuthStyle: oauth2.AuthStyleInParams,
	}

	// The token source outlives the Configure RPC, so it must not inherit its cancellation.
	tokenHTTP := cleanhttp.DefaultPooledClient()
	tokenHTTP.Timeout = 30 * time.Second
	tokenCtx := context.WithValue(context.WithoutCancel(ctx), oauth2.HTTPClient, tokenHTTP)
	ts := cc.TokenSource(tokenCtx)

	if _, err := ts.Token(); err != nil {
		return nil, fmt.Errorf("fetching access token from %s: %w", cc.TokenURL, err)
	}

	retrying := retryablehttp.NewClient()
	retrying.Logger = nil
	retrying.RetryMax = 4
	retrying.HTTPClient = &http.Client{
		Timeout: 60 * time.Second,
		Transport: &oauth2.Transport{
			Source: ts,
			Base:   cleanhttp.DefaultPooledTransport(),
		},
	}

	c, err := NewClientWithResponses(
		endpoint.String()+apiBasePath,
		WithHTTPClient(retrying.StandardClient()),
		WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
			req.Header.Set("User-Agent", cfg.UserAgent)
			return nil
		}),
	)
	if err != nil {
		return nil, err
	}
	return &Manifold{c}, nil
}

// ListAllGovernancePolicies walks every page; params.Cursor and params.Limit are managed here.
func (m *Manifold) ListAllGovernancePolicies(ctx context.Context, params ListGovernancePoliciesParams) ([]GovernancePolicySummary, error) {
	limit := maxPageSize
	params.Limit = &limit
	params.Cursor = nil

	var out []GovernancePolicySummary
	for {
		resp, err := m.ListGovernancePoliciesWithResponse(ctx, &params)
		if err != nil {
			return nil, err
		}
		if resp.JSON200 == nil {
			return nil, NewAPIError(resp.StatusCode(), resp.Body)
		}
		out = append(out, resp.JSON200.Data...)
		if !resp.JSON200.HasNext || resp.JSON200.NextCursor == nil {
			return out, nil
		}
		params.Cursor = resp.JSON200.NextCursor
	}
}

type APIError struct {
	StatusCode int
	Problem    *Problem
}

func NewAPIError(status int, body []byte) error {
	e := &APIError{StatusCode: status}
	var p Problem
	if json.Unmarshal(body, &p) == nil && p.Title != "" {
		e.Problem = &p
	}
	return e
}

func (e *APIError) Error() string {
	if e.Problem == nil {
		return fmt.Sprintf("management API returned HTTP %d", e.StatusCode)
	}
	msg := fmt.Sprintf("management API returned HTTP %d: %s", e.StatusCode, e.Problem.Title)
	if e.Problem.Detail != nil {
		msg += ": " + *e.Problem.Detail
	}
	if e.Problem.RequestId != nil {
		msg += fmt.Sprintf(" (request_id %s)", *e.Problem.RequestId)
	}
	return msg
}

func IsNotFound(err error) bool {
	var e *APIError
	return errors.As(err, &e) && e.StatusCode == http.StatusNotFound
}
