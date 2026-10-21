package provider

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/manifold-security/terraform-provider-manifold/internal/client"
)

const accPrefix = "tf-acc-"

func TestMain(m *testing.M) {
	resource.TestMain(m)
}

func init() {
	resource.AddTestSweepers("manifold_governance_policy", &resource.Sweeper{
		Name: "manifold_governance_policy",
		F: func(_ string) error {
			ctx := context.Background()
			c, err := accClient(ctx)
			if err != nil {
				return err
			}
			q, managed := accPrefix, false
			policies, err := c.ListAllGovernancePolicies(ctx, client.ListGovernancePoliciesParams{Q: &q, IsManaged: &managed})
			if err != nil {
				return err
			}
			for _, p := range policies {
				if !strings.HasPrefix(p.Title, accPrefix) {
					continue
				}
				r, err := c.DeleteGovernancePolicyWithResponse(ctx, p.PolicyId, &client.DeleteGovernancePolicyParams{})
				if err != nil {
					return err
				}
				if s := r.StatusCode(); s != 204 && s != 404 {
					return fmt.Errorf("deleting %s: %w", p.PolicyId, client.NewAPIError(s, r.Body))
				}
			}
			return nil
		},
	})
}

// accClient talks to the acceptance-test tenant directly, for out-of-band changes and destroy checks.
func accClient(ctx context.Context) (*client.Manifold, error) {
	authDomain := os.Getenv("MANIFOLD_AUTH_DOMAIN")
	if authDomain == "" {
		authDomain = defaultAuthDomain
	}
	return client.New(ctx, client.Config{
		Endpoint:     os.Getenv("MANIFOLD_ENDPOINT"),
		TokenURL:     "https://" + authDomain + "/oauth/token",
		ClientID:     os.Getenv("MANIFOLD_CLIENT_ID"),
		ClientSecret: os.Getenv("MANIFOLD_CLIENT_SECRET"),
		Organization: os.Getenv("MANIFOLD_ORGANIZATION"),
		UserAgent:    "terraform-provider-manifold/acctest",
	})
}

func mustAccClient(t *testing.T) *client.Manifold {
	t.Helper()
	c, err := accClient(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return c
}
