package provider

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"manifold": providerserver.NewProtocol6WithError(New("test")()),
}

func TestProviderSchema(t *testing.T) {
	srv, err := testAccProtoV6ProviderFactories["manifold"]()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.GetProviderSchema(t.Context(), &tfprotov6.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range resp.Diagnostics {
		t.Errorf("%s: %s", d.Summary, d.Detail)
	}
	for _, name := range []string{"manifold_governance_policy", "manifold_governance_policies"} {
		if _, ok := resp.DataSourceSchemas[name]; !ok {
			t.Errorf("data source %s not registered", name)
		}
	}
}

func testAccPreCheck(t *testing.T) {
	t.Helper()
	for _, env := range []string{"MANIFOLD_ENDPOINT", "MANIFOLD_CLIENT_ID", "MANIFOLD_CLIENT_SECRET", "MANIFOLD_ORGANIZATION"} {
		if os.Getenv(env) == "" {
			t.Fatalf("%s must be set for acceptance tests", env)
		}
	}
}
