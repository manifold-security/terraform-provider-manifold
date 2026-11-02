resource "manifold_threat_detection_rule" "example" {
  id       = "EXAMPLE-001"
  severity = "critical"
}

# Switch off every rule mapped to a framework, without pasting their ids.
data "manifold_threat_detection_rules" "framework" {
  framework = "EXAMPLE-FRAMEWORK"
}

resource "manifold_threat_detection_rule" "framework" {
  for_each = { for r in data.manifold_threat_detection_rules.framework.rules : r.id => r }

  id      = each.key
  enabled = false
}
