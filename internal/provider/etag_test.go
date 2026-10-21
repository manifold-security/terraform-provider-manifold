package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

type fakePrivate map[string][]byte

func (f fakePrivate) GetKey(_ context.Context, key string) ([]byte, diag.Diagnostics) {
	return f[key], nil
}

func TestReadETagFailsClosed(t *testing.T) {
	if _, diags := readETag(t.Context(), fakePrivate{}); !diags.HasError() {
		t.Fatal("expected an error when no ETag is stored")
	}

	etag, diags := readETag(t.Context(), fakePrivate{etagKey: []byte(`"\"2026-10-21T14:24:23Z\""`)})
	if diags.HasError() {
		t.Fatal(diags)
	}
	if want := `"2026-10-21T14:24:23Z"`; etag == nil || *etag != want {
		t.Fatalf("etag = %v, want %s", etag, want)
	}
}
