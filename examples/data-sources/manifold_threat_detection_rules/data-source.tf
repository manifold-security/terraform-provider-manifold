data "manifold_threat_detection_rules" "disabled" {
  enabled = false
}

output "disabled_rule_ids" {
  value = [for r in data.manifold_threat_detection_rules.disabled.rules : r.id]
}
