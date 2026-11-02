package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	"github.com/manifold-security/terraform-provider-manifold/internal/client"
)

const ruleAddr = "manifold_threat_detection_rule.test"

// The rule is discovered at runtime and its original tuning kept in terraform_data, so the test tunes away from it and back.
func ruleConfig(tuning string) string {
	return `
data "manifold_threat_detection_rules" "all" {}

resource "terraform_data" "original" {
  input = data.manifold_threat_detection_rules.all.rules[0]

  lifecycle {
    ignore_changes = [input]
  }
}

locals {
  original = terraform_data.original.output
}

resource "manifold_threat_detection_rule" "test" {
  id = local.original.id
` + tuning + `
}
`
}

const (
	retuned  = "  enabled  = !local.original.enabled\n  severity = local.original.severity == \"low\" ? \"medium\" : \"low\""
	restored = "  enabled  = local.original.enabled\n  severity = local.original.severity"
)

func TestAccThreatDetectionRuleResource_lifecycle(t *testing.T) {
	var c *client.Manifold
	var ruleID string

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
			c = mustAccClient(t)
			restoreRuleTuningOnCleanup(t, c)
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: ruleConfig(""),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.CompareValuePairs(
						"terraform_data.original", tfjsonpath.New("output").AtMapKey("severity"),
						ruleAddr, tfjsonpath.New("severity"), compare.ValuesSame()),
					statecheck.CompareValuePairs(
						"terraform_data.original", tfjsonpath.New("output").AtMapKey("enabled"),
						ruleAddr, tfjsonpath.New("enabled"), compare.ValuesSame()),
				},
			},
			{
				Config: ruleConfig(retuned),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(ruleAddr, plancheck.ResourceActionUpdate)},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.CompareValuePairs(
						"terraform_data.original", tfjsonpath.New("output").AtMapKey("enabled"),
						ruleAddr, tfjsonpath.New("enabled"), compare.ValuesDiffer()),
				},
				Check: func(s *terraform.State) error {
					ruleID = s.RootModule().Resources[ruleAddr].Primary.ID
					return nil
				},
			},
			{
				ResourceName:      ruleAddr,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:  ruleAddr,
				ImportState:   true,
				ImportStateId: "tf-acc-no-such-rule",
				ExpectError:   regexp.MustCompile(`Cannot import non-existent remote object`),
			},
			{
				PreConfig: func() { retuneRuleOutOfBand(t, c, ruleID) },
				Config:    ruleConfig(retuned),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(ruleAddr, plancheck.ResourceActionUpdate)},
				},
			},
			{
				Config: ruleConfig(restored),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.CompareValuePairs(
						"terraform_data.original", tfjsonpath.New("output").AtMapKey("severity"),
						ruleAddr, tfjsonpath.New("severity"), compare.ValuesSame()),
					statecheck.CompareValuePairs(
						"terraform_data.original", tfjsonpath.New("output").AtMapKey("enabled"),
						ruleAddr, tfjsonpath.New("enabled"), compare.ValuesSame()),
				},
			},
		},
	})
}

func TestAccThreatDetectionRuleResource_unknownRule(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "manifold_threat_detection_rule" "test" {
  id      = "tf-acc-no-such-rule"
  enabled = false
}
`,
				ExpectError: regexp.MustCompile(`Detection rule not found`),
			},
		},
	})
}

// restoreRuleTuningOnCleanup puts every rule back the way it was if a failed run leaves one retuned on the shared tenant.
func restoreRuleTuningOnCleanup(t *testing.T, c *client.Manifold) {
	t.Helper()
	before, err := c.ListAllThreatDetectionRules(t.Context(), client.ListThreatDetectionRulesParams{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		after, err := c.ListAllThreatDetectionRules(t.Context(), client.ListThreatDetectionRulesParams{})
		if err != nil {
			t.Error(err)
			return
		}
		now := map[string]client.ThreatDetectionRuleSummary{}
		for _, r := range after {
			now[r.DetectionRuleId] = r
		}
		for _, r := range before {
			cur, ok := now[r.DetectionRuleId]
			if !ok || (cur.Enabled == r.Enabled && cur.Severity == r.Severity) {
				continue
			}
			sev := client.SeverityInput(r.Severity)
			out, err := c.UpdateThreatDetectionRuleWithResponse(t.Context(), r.DetectionRuleId, &client.UpdateThreatDetectionRuleParams{},
				client.ThreatDetectionRuleUpdate{Enabled: &r.Enabled, Severity: &sev})
			if err == nil && out.JSON200 == nil {
				err = client.NewAPIError(out.StatusCode(), out.Body)
			}
			if err != nil {
				t.Errorf("restoring %s: %v", r.DetectionRuleId, err)
			}
		}
	})
}

func retuneRuleOutOfBand(t *testing.T, c *client.Manifold, id string) {
	t.Helper()
	rule, err := c.GetThreatDetectionRuleWithResponse(t.Context(), id)
	if err == nil && rule.JSON200 == nil {
		err = client.NewAPIError(rule.StatusCode(), rule.Body)
	}
	if err != nil {
		t.Fatal(err)
	}
	enabled := !rule.JSON200.Enabled
	out, err := c.UpdateThreatDetectionRuleWithResponse(t.Context(), id, &client.UpdateThreatDetectionRuleParams{},
		client.ThreatDetectionRuleUpdate{Enabled: &enabled})
	if err == nil && out.JSON200 == nil {
		err = client.NewAPIError(out.StatusCode(), out.Body)
	}
	if err != nil {
		t.Fatal(err)
	}
}
