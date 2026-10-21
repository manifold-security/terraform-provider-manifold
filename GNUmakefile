SPEC_REF ?= origin/main
CORE_DIR ?= ../core
TF_BIN   ?= tofu
SCHEMA   := .schema/schema.json

default: fmt lint install generate

build:
	go build -v ./...

install: build
	go install -v ./...

lint:
	golangci-lint run

fmt:
	gofmt -s -w -e .
	$(TF_BIN) fmt -recursive examples/

test:
	go test -v -cover -timeout=120s -parallel=10 ./...

# Runs against a real instance; see README for the MANIFOLD_* variables.
testacc:
	TF_ACC=1 TF_ACC_TERRAFORM_PATH=$$(command -v $(TF_BIN)) TF_ACC_PROVIDER_NAMESPACE=manifold-security \
		go test -v -cover -timeout 120m ./...

# Deletes tf-acc-* policies leaked by interrupted acceptance runs.
sweep:
	go test ./internal/provider -v -sweep=default -timeout 10m

# Refreshes the vendored management API spec from core.
spec:
	git -C $(CORE_DIR) fetch -q origin
	git -C $(CORE_DIR) show $(SPEC_REF):apps/api-server/api/management/v1/openapi.yaml > api/management-v1.yaml

generate: install
	go generate ./...
	@mkdir -p .schema
	printf 'provider_installation {\n  dev_overrides { "manifold-security/manifold" = "%s" }\n  direct {}\n}\n' "$$(go env GOPATH)/bin" > .schema/cli.tfrc
	cd examples/provider && TF_CLI_CONFIG_FILE=../../.schema/cli.tfrc $(TF_BIN) providers schema -json \
		| jq '.provider_schemas |= with_entries(.key = "manifold")' > ../../$(SCHEMA)
	go tool -modfile=tools/go.mod tfplugindocs generate --provider-name manifold --providers-schema $(SCHEMA)

.PHONY: default build install lint fmt test testacc sweep spec generate
