data "manifold_threat_detection_rule" "example" {
  id = "EXAMPLE-001"
}

output "what_it_detects" {
  value = data.manifold_threat_detection_rule.example.what_it_detects
}
