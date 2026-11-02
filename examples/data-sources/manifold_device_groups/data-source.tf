data "manifold_device_groups" "all" {}

locals {
  example_group_id = one([for g in data.manifold_device_groups.all.groups : g.id if g.name == "Example group"])
}
