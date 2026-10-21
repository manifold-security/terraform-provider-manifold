resource "manifold_governance_policy" "no_prod_db_writes" {
  title       = "Block writes to production databases"
  description = "Agents must not run mutating SQL against production."
  category    = "DATA"
  action      = "correct"
  severity    = "high"
  priority    = 10

  response_message  = "{{ .Title }}: use the staging database or ask the on-call DBA."
  taxonomy_mappings = ["OWASP-ASI02"]

  cedar_policy = <<-EOT
    forbid(principal, action, resource is Event::Tool)
    when {
      resource.input like "*prod-db*" &&
      (resource.input like "*INSERT*" || resource.input like "*UPDATE*" || resource.input like "*DELETE*")
    };
  EOT

  action_options = {
    notify_user = true
  }
}
