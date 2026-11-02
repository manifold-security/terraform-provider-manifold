# terraform-provider-manifold

Manage your [Manifold](https://www.manifold.security) configuration as code. The provider talks to the Manifold [management API](https://docs.manifoldsecurity.io/api-reference/management-api) and works with both Terraform and OpenTofu, so platform settings can live in version control and change through the same review process as the rest of your infrastructure.

It covers governance policies and threat detection rules today, and more of the management API will follow.

| Kind | Name | What it does |
| --- | --- | --- |
| Resource | `manifold_governance_policy` | Creates, updates and deletes customer-authored policies. Import takes the policy UUID. |
| Data source | `manifold_governance_policy` | Reads one policy by id, Cedar rule included. |
| Data source | `manifold_governance_policies` | Lists the catalog, managed and customer-authored, with optional filters. |
| Resource | `manifold_threat_detection_rule` | Tunes a built-in detection rule (`enabled`, `severity`). Import takes the rule id. |
| Data source | `manifold_threat_detection_rule` | Reads one detection rule by id, with what it detects. |
| Data source | `manifold_threat_detection_rules` | Lists detection rules with optional filters. |

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
| `read:policies` | governance policy data sources, plan, refresh |
| `write:policies` | governance policy create, update, delete |
| `read:threats` | detection rule data sources, plan, refresh |
| `write:threats` | detection rule tuning |

Grant only the scopes for what your configuration manages.

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
make spec        # maintainers: refreshes api/management-v1.yaml from the docs repo
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

### Acceptance tests

The acceptance tests (`TestAcc*`) drive the real CLI binary against a live Manifold instance and only run under `make testacc`. They need an OIDC client with `read:policies`, `write:policies`, `read:threats` and `write:threats`, and the `MANIFOLD_*` variables from [Authentication](#authentication) exported in your shell. CI runs them on `main` from the `acceptance` environment and skips the job when it isn't configured.

Each test creates the policies it needs and titles them `tf-acc-*`. A run that dies halfway can leave some behind; `make sweep` deletes them. Detection rules can't be created, so the rule test retunes whichever rule the list returns first and puts it back afterwards.

## Design notes

The provider is built on [terraform-plugin-framework](https://developer.hashicorp.com/terraform/plugin/framework). HashiCorp recommends it over SDKv2 for new providers, and a depguard rule stops SDKv2 imports from creeping in.

`internal/client/client.gen.go` is generated by oapi-codegen from `api/management-v1.yaml`, a copy of the published management API spec. Only the operations listed in `internal/client/oapi-codegen.yaml` get generated, so covering a new part of the API starts with adding its operations there. Hand-written client code (auth, retries, paging, errors) is in `client.go` next to it.

The schema stays close to the API, as the [provider design principles](https://developer.hashicorp.com/terraform/plugin/best-practices/hashicorp-provider-design-principles) suggest. The one rename is `policy_id`, which becomes `id`. Timestamps are RFC 3339, and a `response_message` the API omits shows up as null.

Policies with `is_managed = true` belong to Manifold and the API won't let anyone edit or delete them. The data sources return them, but the resource refuses to import them.

The resource stores the `ETag` from its last read in private state and sends it as `If-Match` on update and delete. If someone edits the policy in the dashboard between plan and apply, the apply fails rather than silently overwriting their change. Edits made before the plan just appear as drift.

`severity`, `enabled`, `priority`, `action_options` and `taxonomy_mappings` have the API's defaults written into the schema. Deleting one of them from your config puts the policy back to the default instead of leaving whatever value it had last.

Detection rules are Manifold's and can't be created or deleted, so `manifold_threat_detection_rule` adopts an existing rule by id and manages only the attributes you set. The API doesn't expose a rule's defaults, so there is nothing to reset to: leaving `enabled` or `severity` out keeps its current value, and destroying the resource only removes it from state, with the rule keeping its last tuning. Rule updates use the same `ETag`/`If-Match` guard as policies.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report security issues privately as described in [SECURITY.md](SECURITY.md).

## License

Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
