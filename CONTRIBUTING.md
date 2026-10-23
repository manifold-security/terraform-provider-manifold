# Contributing to terraform-provider-manifold

Thanks for considering a contribution. Most useful are bug reports with a configuration that reproduces them, and support for more of the management API.

## What the provider covers

It manages Manifold settings through the published [management API](https://docs.manifoldsecurity.io/api-reference/management-api), and nothing else. A resource or attribute has to map to an operation in that spec. If the API doesn't expose something, the provider can't manage it, however useful it would be; open an issue instead so we can look at the API side.

The schema follows the API, as the [provider design principles](https://developer.hashicorp.com/terraform/plugin/best-practices/hashicorp-provider-design-principles) suggest. Renames, merged attributes or computed conveniences need a reason in the pull request.

## Adding part of the API

1. Add the operations to `internal/client/oapi-codegen.yaml` and run `make generate`. The client in `client.gen.go` is generated; don't edit it by hand.
2. Write the resource or data source in `internal/provider` and register it in `provider.go`.
3. Add an example under `examples/` and a description on every attribute. `make generate` builds `docs/` from both.
4. Add unit tests and an acceptance test. Acceptance tests title what they create `tf-acc-*` and register a sweeper so `make sweep` can clean up after an interrupted run.

The provider is built on terraform-plugin-framework. SDKv2 imports fail the lint.

## Tests and gates

```sh
make test       # unit tests, no network
make lint       # golangci-lint
make generate   # client and docs; CI fails if the result isn't committed
```

Everything must be green before you open a pull request. CI runs the same checks.

Acceptance tests (`make testacc`) need a Manifold instance and an OIDC client that can write policies, so they aren't required for outside contributions. Maintainers run them on `main`. If you have an instance, the README explains how to run them yourself.

## Commits

Conventional Commits, one logical change per commit. The commit message is where the reasoning goes, so explain why the change is needed rather than restating the diff.

## Contribution terms

The provider is licensed under Apache-2.0. Under section 5 of the [LICENSE](LICENSE), a contribution you submit for inclusion is licensed under the same terms, with no additional terms or conditions, unless you explicitly state otherwise.

Each commit must carry a sign-off certifying the [Developer Certificate of Origin 1.1](https://developercertificate.org/). Add it with `git commit -s`, which appends a `Signed-off-by:` line with your committer name and email.

## Code of conduct

Everyone taking part in this project is expected to follow the [code of conduct](CODE_OF_CONDUCT.md).

## Reporting a problem

Open an issue with the configuration that produced the wrong result (credentials and endpoints removed), the provider and CLI versions, the output you got and the output you expected. Security issues go through [SECURITY.md](SECURITY.md) instead.
