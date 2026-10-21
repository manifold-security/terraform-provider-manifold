terraform {
  required_providers {
    manifold = {
      source = "manifold-security/manifold"
    }
  }
}

# Credentials are usually supplied via MANIFOLD_CLIENT_ID / MANIFOLD_CLIENT_SECRET.
provider "manifold" {
  endpoint     = "https://acme.app.manifoldsecurity.io"
  organization = "org_abc123"
}
