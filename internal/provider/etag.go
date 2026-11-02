package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

const etagKey = "etag"

type stateSetter interface {
	Set(ctx context.Context, val any) diag.Diagnostics
}

type privateState interface {
	SetKey(ctx context.Context, key string, value []byte) diag.Diagnostics
}

type privateReader interface {
	GetKey(ctx context.Context, key string) ([]byte, diag.Diagnostics)
}

// storeETag keeps the response's ETag in private state, or clears it when the response has none.
func storeETag(ctx context.Context, httpResp *http.Response, private privateState) diag.Diagnostics {
	var raw []byte
	if etag := httpResp.Header.Get("ETag"); etag != "" {
		raw, _ = json.Marshal(etag)
	}
	return private.SetKey(ctx, etagKey, raw)
}

func readETag(ctx context.Context, private privateReader, what string) (*string, diag.Diagnostics) {
	raw, diags := private.GetKey(ctx, etagKey)
	if diags.HasError() {
		return nil, diags
	}
	if len(raw) == 0 {
		diags.AddError("Missing ETag for "+what,
			fmt.Sprintf("The last read of this %s returned no ETag, so the change can't be guarded against concurrent edits and was not sent. Run plan again to refresh it.", what))
		return nil, diags
	}
	var etag string
	if err := json.Unmarshal(raw, &etag); err != nil {
		diags.AddError("Corrupt private state", err.Error())
		return nil, diags
	}
	return &etag, diags
}
