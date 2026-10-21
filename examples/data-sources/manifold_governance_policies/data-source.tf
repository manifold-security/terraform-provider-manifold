data "manifold_governance_policies" "blocking" {
  actions    = ["block", "block_session"]
  is_managed = false
}

output "blocking_titles" {
  value = [for p in data.manifold_governance_policies.blocking.policies : p.title]
}
