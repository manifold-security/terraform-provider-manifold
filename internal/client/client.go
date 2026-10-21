package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
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
	endpoint, err := secureURL(strings.TrimRight(cfg.Endpoint, "/"))
	if err != nil {
		return nil, fmt.Errorf("endpoint: %w", err)
	}
	if _, err := secureURL(cfg.TokenURL); err != nil {
		return nil, fmt.Errorf("token URL: %w", err)
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
	tokenHTTP.CheckRedirect = refuseRedirect
	tokenCtx := context.WithValue(context.WithoutCancel(ctx), oauth2.HTTPClient, tokenHTTP)
	ts := cc.TokenSource(tokenCtx)

	if _, err := ts.Token(); err != nil {
		return nil, fmt.Errorf("fetching access token from %s: %w", cc.TokenURL, err)
	}

	retrying := retryablehttp.NewClient()
	retrying.Logger = nil
	retrying.RetryMax = 4
	retrying.CheckRetry = retryPolicy
	retrying.HTTPClient = &http.Client{
		Timeout:       60 * time.Second,
		CheckRedirect: refuseRedirect,
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

// secureURL accepts https, or plain http to a loopback host for local testing.
func secureURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("%q must be an absolute URL such as https://acme.app.manifoldsecurity.io", raw)
	}
	if u.Scheme == "https" {
		return u, nil
	}
	if ip := net.ParseIP(u.Hostname()); u.Scheme == "http" && (u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())) {
		return u, nil
	}
	return nil, fmt.Errorf("%q must use https", raw)
}

var errRedirect = errors.New("refusing redirect")

// The API never redirects; following one would hand the bearer token to wherever it points.
func refuseRedirect(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("%w to %s", errRedirect, req.URL.Redacted())
}

func retryPolicy(ctx context.Context, resp *http.Response, err error) (bool, error) {
	if errors.Is(err, errRedirect) {
		return false, err
	}
	return retryablehttp.DefaultRetryPolicy(ctx, resp, err)
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
	if e.Problem.Errors != nil {
		for _, fe := range *e.Problem.Errors {
			msg += fmt.Sprintf("\n  %s: %s", fe.Field, fe.Code)
			if fe.Message != nil {
				msg += " (" + *fe.Message + ")"
			}
		}
	}
	return msg
}

func IsNotFound(err error) bool {
	return hasStatus(err, http.StatusNotFound)
}

func IsPreconditionFailed(err error) bool {
	return hasStatus(err, http.StatusPreconditionFailed)
}

func hasStatus(err error, status int) bool {
	var e *APIError
	return errors.As(err, &e) && e.StatusCode == status
}
