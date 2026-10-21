data "manifold_governance_policy" "example" {
  id = "3f0b8c1e-5d2a-4c7e-9b1f-2a6d8e4c0f17"
}

output "rule" {
  value = data.manifold_governance_policy.example.cedar_policy
}
