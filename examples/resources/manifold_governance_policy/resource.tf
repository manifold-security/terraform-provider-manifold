resource "manifold_governance_policy" "block_tagged_assets" {
  title       = "Block assets tagged blocked"
  description = "Agents must not use any asset an admin has tagged blocked."
  category    = "USAGE"
  action      = "block"
  severity    = "high"
  priority    = 10

  response_message  = "{{ .Title }}: this asset is not approved for use."
  taxonomy_mappings = ["OWASP-ASI02"]

  cedar_policy = <<-EOT
    forbid(principal, action, resource)
    when {
      context has "involved_asset_tags" && context.involved_asset_tags.contains("blocked")
    };
  EOT

  action_options = {
    notify_user = true
  }
}
