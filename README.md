# terraform-provider-manifold

Manage your [Manifold](https://www.manifold.security) configuration as code. The provider talks to the Manifold [management API](https://docs.manifoldsecurity.io/api-reference/management-api) and works with both Terraform and OpenTofu, so platform settings can live in version control and change through the same review process as the rest of your infrastructure.

It covers governance policies today, and more of the management API will follow.

| Kind | Name | What it does |
| --- | --- | --- |
| Resource | `manifold_governance_policy` | Creates, updates and deletes customer-authored policies. Import takes the policy UUID. |
| Data source | `manifold_governance_policy` | Reads one policy by id, Cedar rule included. |
| Data source | `manifold_governance_policies` | Lists the catalog, managed and customer-authored, with optional filters. |

Full reference docs are in [`docs/`](docs/), with working configurations in [`examples/`](examples/).

## Usage

```hcl
terraform {
  required_providers {
    manifold = {
      source = "manifold-security/manifold"
    }
  }
}

provider "manifold" {
  endpoint     = "https://acme.app.manifoldsecurity.io"
  organization = "org_abc123"
  # client_id and client_secret usually come from MANIFOLD_CLIENT_ID and MANIFOLD_CLIENT_SECRET.
}

resource "manifold_governance_policy" "no_openclaw" {
  title        = "Block openclaw"
  description  = "openclaw is not approved for use."
  category     = "USAGE"
  action       = "block"
  cedar_policy = "forbid(principal == Agent::\"openclaw\", action, resource);"
}
```

## Authentication

The provider logs in as an OIDC client using the OAuth2 client credentials flow. A dashboard admin creates the client under Settings → Access → Credentials → OIDC clients. The dashboard shows the secret once. Scopes can't be changed after creation and secrets can't be rotated, so if either needs to change, create a new client.

| Scope | Needed for |
| --- | --- |
| `read:policies` | data sources, plan, refresh |
| `write:policies` | create, update, delete |

| Attribute | Env var | Example |
| --- | --- | --- |
| `endpoint` | `MANIFOLD_ENDPOINT` | `https://acme.app.manifoldsecurity.io` |
| `auth_domain` | `MANIFOLD_AUTH_DOMAIN` | `auth.manifoldsecurity.io` (default) |
| `organization` | `MANIFOLD_ORGANIZATION` | `org_abc123` |
| `client_id` | `MANIFOLD_CLIENT_ID` | |
| `client_secret` | `MANIFOLD_CLIENT_SECRET` | |

You don't configure the token URL, audience or API path. The provider requests tokens from `https://<auth_domain>/oauth/token` with audience `<endpoint>/management/api` and calls the API at `<endpoint>/api/management/v1`. Both must be https. Tokens expire after 15 minutes and the provider fetches a new one when that happens. It retries 429 and 5xx responses and waits as long as `Retry-After` asks.

## Development

You need Go (version in `go.mod`), `jq`, golangci-lint v2, and either OpenTofu or Terraform. The Makefile calls `tofu` by default; pass `TF_BIN=terraform` to use Terraform instead.

```sh
make install     # builds into $(go env GOPATH)/bin
make test        # unit tests, no network
make lint
make generate    # regenerates the API client and docs; CI fails if they drift
make spec        # refreshes api/management-v1.yaml from ../core origin/main
```

To run your own configs against a local build, add a dev override to your CLI config file. That's `~/.terraformrc` for Terraform, `~/.tofurc` for OpenTofu, or whatever file `TF_CLI_CONFIG_FILE` points at:

```hcl
provider_installation {
  dev_overrides {
    "manifold-security/manifold" = "/Users/<you>/go/bin"
  }
  direct {}
}
```

With the override in place you can run plan and apply straight away; `init` isn't needed for the overridden provider. Take the override out when you're done, or every other config that uses this provider will pick up the dev build too.

### Testing against a dev tenant

Dev instances run at `<name>.demo.manifoldsecurity.io` and get tokens from `auth.manifoldsecurity.dev`. Most people share `sandbox`. Create an OIDC client with `read:policies` and `write:policies` in that instance's dashboard, then:

```sh
export MANIFOLD_ENDPOINT=https://sandbox.demo.manifoldsecurity.io
export MANIFOLD_AUTH_DOMAIN=auth.manifoldsecurity.dev
export MANIFOLD_ORGANIZATION=org_...
export MANIFOLD_CLIENT_ID=...
export MANIFOLD_CLIENT_SECRET=...
make testacc
```

The acceptance tests (`TestAcc*`) drive the real CLI binary and only run under `make testacc`. CI reads the same variables from the repo's `vars` and `secrets`, and skips the job when they aren't set.

Each test creates the policies it needs and titles them `tf-acc-*`. A run that dies halfway can leave some behind; `make sweep` deletes them.

## Design notes

The provider is built on [terraform-plugin-framework](https://developer.hashicorp.com/terraform/plugin/framework). HashiCorp recommends it over SDKv2 for new providers, and a depguard rule stops SDKv2 imports from creeping in.

`internal/client/client.gen.go` is generated by oapi-codegen from `api/management-v1.yaml`, a copy of the management API spec. Only the operations listed in `internal/client/oapi-codegen.yaml` get generated, so covering a new part of the API starts with adding its operations there. Hand-written client code (auth, retries, paging, errors) is in `client.go` next to it.

The schema stays close to the API, as the [provider design principles](https://developer.hashicorp.com/terraform/plugin/best-practices/hashicorp-provider-design-principles) suggest. The one rename is `policy_id`, which becomes `id`. Timestamps are RFC 3339, and a `response_message` the API omits shows up as null.

Policies with `is_managed = true` belong to Manifold and the API won't let anyone edit or delete them. The data sources return them, but the resource refuses to import them.

The resource stores the `ETag` from its last read in private state and sends it as `If-Match` on update and delete. If someone edits the policy in the dashboard between plan and apply, the apply fails rather than silently overwriting their change. Edits made before the plan just appear as drift.

`severity`, `enabled`, `priority`, `action_options` and `taxonomy_mappings` have the API's defaults written into the schema. Deleting one of them from your config puts the policy back to the default instead of leaving whatever value it had last.

## License

Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
