package provider

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/manifold-security/terraform-provider-manifold/internal/client"
)

func TestDeviceGroupsDataSource(t *testing.T) {
	h := newHarness(t)
	id := uuid.New()
	h.api.groups = []client.CustomDeviceGroup{{
		Id:          id,
		Name:        "Example group",
		MemberCount: 3,
		CreatedAt:   time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}}
	h.api.failWith("GET /devices/groups", http.StatusServiceUnavailable)

	state, diags := h.readData("manifold_device_groups", nil)
	h.noErrors(diags)
	if got := attrOf(t, state, "groups", 0, "id"); got != id.String() {
		t.Errorf("id = %v, want %s", got, id)
	}
	if got := attrOf(t, state, "groups", 0, "description"); got != "" {
		t.Errorf("description = %v, want empty", got)
	}
	if n := h.api.count("GET /devices/groups"); n != 2 {
		t.Errorf("list sent %d times, want a retry after the 503", n)
	}
}

func TestDeviceGroupsDataSourceEmpty(t *testing.T) {
	h := newHarness(t)

	state, diags := h.readData("manifold_device_groups", nil)
	h.noErrors(diags)
	if n := attrOf(t, state, "groups"); n != 0 {
		t.Errorf("got %v groups, want none", n)
	}
}
