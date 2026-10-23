package provider

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	"github.com/manifold-security/terraform-provider-manifold/internal/client"
)

const policyAddr = "manifold_governance_policy.test"

func minimalPolicyConfig(name string) string {
	return fmt.Sprintf(`
resource "manifold_governance_policy" "test" {
  title        = %[1]q
  description  = "Created by terraform-provider-manifold acceptance tests."
  category     = "USAGE"
  action       = "alert"
  cedar_policy = <<-EOT
    forbid(principal == Agent::"%[1]s", action, resource);
  EOT
}
`, name)
}

func fullPolicyConfig(name string) string {
	return fmt.Sprintf(`
resource "manifold_governance_policy" "test" {
  title             = "%[1]s-updated"
  description       = "Updated by terraform-provider-manifold acceptance tests."
  category          = "EXECUTION"
  action            = "advise"
  response_message  = "{{ .Title }} applies here."
  severity          = "high"
  enabled           = false
  priority          = 5
  taxonomy_mappings = ["OWASP-ASI02", "ATLAS-AML.M0021"]
  cedar_policy      = <<-EOT
    forbid(principal == Agent::"%[1]s", action, resource is Event::Tool);
  EOT

  action_options = {
    notify_user = true
  }
}
`, name)
}

func TestAccGovernancePolicyResource_lifecycle(t *testing.T) {
	name := accPrefix + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	sameID := statecheck.CompareValue(compare.ValuesSame())
	var c *client.Manifold

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
			c = mustAccClient(t)
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             func(s *terraform.State) error { return checkPoliciesDestroyed(t.Context(), c, s) },
		Steps: []resource.TestStep{
			{
				Config: minimalPolicyConfig(name),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(policyAddr, plancheck.ResourceActionCreate)},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					sameID.AddStateValue(policyAddr, tfjsonpath.New("id")),
					statecheck.ExpectKnownValue(policyAddr, tfjsonpath.New("severity"), knownvalue.StringExact("medium")),
					statecheck.ExpectKnownValue(policyAddr, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(policyAddr, tfjsonpath.New("priority"), knownvalue.Int32Exact(0)),
					statecheck.ExpectKnownValue(policyAddr, tfjsonpath.New("action_options").AtMapKey("notify_user"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(policyAddr, tfjsonpath.New("taxonomy_mappings"), knownvalue.ListExact([]knownvalue.Check{})),
					statecheck.ExpectKnownValue(policyAddr, tfjsonpath.New("response_message"), knownvalue.Null()),
					statecheck.ExpectKnownValue(policyAddr, tfjsonpath.New("is_managed"), knownvalue.Bool(false)),
				},
			},
			{
				ResourceName:      policyAddr,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:  policyAddr,
				ImportState:   true,
				ImportStateId: "not-a-uuid",
				ExpectError:   regexp.MustCompile(`Expected a policy UUID`),
			},
			{
				// A description-only edit sends just that field, so the stored Cedar isn't re-validated.
				Config: strings.Replace(minimalPolicyConfig(name), "Created by", "Edited by", 1),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(policyAddr, plancheck.ResourceActionUpdate)},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					sameID.AddStateValue(policyAddr, tfjsonpath.New("id")),
					statecheck.ExpectKnownValue(policyAddr, tfjsonpath.New("description"),
						knownvalue.StringExact("Edited by terraform-provider-manifold acceptance tests.")),
				},
			},
			{
				Config: fullPolicyConfig(name),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(policyAddr, plancheck.ResourceActionUpdate)},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					sameID.AddStateValue(policyAddr, tfjsonpath.New("id")),
					statecheck.ExpectKnownValue(policyAddr, tfjsonpath.New("title"), knownvalue.StringExact(name+"-updated")),
					statecheck.ExpectKnownValue(policyAddr, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(policyAddr, tfjsonpath.New("taxonomy_mappings"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("OWASP-ASI02"),
						knownvalue.StringExact("ATLAS-AML.M0021"),
					})),
				},
			},
			{
				ResourceName:      policyAddr,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				// Dropping optional attributes resets them to their defaults and clears response_message.
				Config: minimalPolicyConfig(name),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(policyAddr, plancheck.ResourceActionUpdate)},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					sameID.AddStateValue(policyAddr, tfjsonpath.New("id")),
					statecheck.ExpectKnownValue(policyAddr, tfjsonpath.New("severity"), knownvalue.StringExact("medium")),
					statecheck.ExpectKnownValue(policyAddr, tfjsonpath.New("response_message"), knownvalue.Null()),
					statecheck.ExpectKnownValue(policyAddr, tfjsonpath.New("taxonomy_mappings"), knownvalue.ListExact([]knownvalue.Check{})),
				},
			},
			{
				PreConfig: func() { editPolicyOutOfBand(t, c, name) },
				Config:    minimalPolicyConfig(name),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(policyAddr, plancheck.ResourceActionUpdate)},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(policyAddr, tfjsonpath.New("title"), knownvalue.StringExact(name)),
					statecheck.ExpectKnownValue(policyAddr, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
				},
			},
			{
				PreConfig: func() { deletePolicyOutOfBand(t, c, name) },
				Config:    minimalPolicyConfig(name),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(policyAddr, plancheck.ResourceActionCreate)},
				},
			},
		},
	})
}

func TestAccGovernancePolicyResource_requiresResponseMessage(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "manifold_governance_policy" "test" {
  title        = "tf-acc-never-created"
  description  = "Never created."
  category     = "USAGE"
  action       = "correct"
  cedar_policy = "forbid(principal, action, resource);"
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Missing response_message`),
			},
		},
	})
}

func TestAccGovernancePolicyResource_apiValidation(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "manifold_governance_policy" "test" {
  title        = "tf-acc-never-created"
  description  = "Never created."
  category     = "USAGE"
  action       = "alert"
  cedar_policy = "permit(principal, action, resource);"
}
`,
				ExpectError: regexp.MustCompile(`use\s+forbid,\s+not\s+permit`),
			},
		},
	})
}

func findPolicyID(t *testing.T, c *client.Manifold, prefix string) uuid.UUID {
	t.Helper()
	q := prefix
	policies, err := c.ListAllGovernancePolicies(t.Context(), client.ListGovernancePoliciesParams{Q: &q})
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected exactly one policy matching %q, got %d", prefix, len(policies))
	}
	return policies[0].PolicyId
}

func editPolicyOutOfBand(t *testing.T, c *client.Manifold, name string) {
	t.Helper()
	title, enabled := name+"-edited-elsewhere", false
	r, err := c.UpdateGovernancePolicyWithResponse(t.Context(), findPolicyID(t, c, name), &client.UpdateGovernancePolicyParams{},
		client.GovernancePolicyUpdate{Title: &title, Enabled: &enabled})
	if err == nil && r.JSON200 == nil {
		err = client.NewAPIError(r.StatusCode(), r.Body)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func deletePolicyOutOfBand(t *testing.T, c *client.Manifold, name string) {
	t.Helper()
	r, err := c.DeleteGovernancePolicyWithResponse(t.Context(), findPolicyID(t, c, name), &client.DeleteGovernancePolicyParams{})
	if err == nil && r.StatusCode() != http.StatusNoContent {
		err = client.NewAPIError(r.StatusCode(), r.Body)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func checkPoliciesDestroyed(ctx context.Context, c *client.Manifold, s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "manifold_governance_policy" {
			continue
		}
		r, err := c.GetGovernancePolicyWithResponse(ctx, uuid.MustParse(rs.Primary.ID))
		if err != nil {
			return err
		}
		if r.StatusCode() != http.StatusNotFound {
			return fmt.Errorf("governance policy %s still exists (HTTP %d)", rs.Primary.ID, r.StatusCode())
		}
	}
	return nil
}
