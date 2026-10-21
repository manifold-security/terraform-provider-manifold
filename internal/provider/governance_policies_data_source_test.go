package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// Relies on the tenant holding at least one alert policy.
func TestAccGovernancePoliciesDataSource(t *testing.T) {
	uuidRe := regexp.MustCompile(`^[0-9a-f-]{36}$`)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "manifold_governance_policies" "alerts" {
  actions = ["alert"]
}

data "manifold_governance_policy" "first" {
  id = data.manifold_governance_policies.alerts.policies[0].id
}
`,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("data.manifold_governance_policies.alerts",
						tfjsonpath.New("policies").AtSliceIndex(0).AtMapKey("action"), knownvalue.StringExact("alert")),
					statecheck.ExpectKnownValue("data.manifold_governance_policy.first",
						tfjsonpath.New("id"), knownvalue.StringRegexp(uuidRe)),
					statecheck.CompareValuePairs(
						"data.manifold_governance_policies.alerts", tfjsonpath.New("policies").AtSliceIndex(0).AtMapKey("title"),
						"data.manifold_governance_policy.first", tfjsonpath.New("title"),
						compare.ValuesSame()),
				},
			},
		},
	})
}

func TestAccGovernancePolicyDataSource_notFound(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "manifold_governance_policy" "missing" {
  id = "00000000-0000-0000-0000-000000000000"
}
`,
				ExpectError: regexp.MustCompile(`HTTP 404`),
			},
		},
	})
}
