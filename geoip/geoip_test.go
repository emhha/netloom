package geoip

import (
	"context"
	"strings"
	"testing"
)

// ---- Service unit tests (no real network, no MMDB files) -------------------

func TestNew_emptyDataDir(t *testing.T) {
	_, err := New("")
	if err == nil {
		t.Error("expected error for empty dataDir")
	}
}

func TestLookup_invalidIP(t *testing.T) {
	svc := &Service{}
	_, err := svc.Lookup(context.Background(), "not-an-ip")
	if err == nil {
		t.Error("expected error for invalid IP")
	}
	if !strings.Contains(err.Error(), "invalid IP") {
		t.Errorf("unexpected error text: %v", err)
	}
}

func TestLookup_noDBLoaded_stillReturnsInfo(t *testing.T) {
	// Service with no DBs loaded should return an IPInfo (degraded, zero fields)
	// rather than an error.
	svc := &Service{}
	info, err := svc.Lookup(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("expected non-nil IPInfo")
	}
	if info.IP != "8.8.8.8" {
		t.Errorf("expected IP=8.8.8.8, got %q", info.IP)
	}
}

func TestLookupBatch_partialErrors(t *testing.T) {
	svc := &Service{}
	results, err := svc.LookupBatch(context.Background(), []string{"8.8.8.8", "bad-ip", "1.1.1.1"})
	if err == nil {
		t.Error("expected non-nil error for bad IP in batch")
	}
	if results[0] == nil {
		t.Error("first result should succeed")
	}
	if results[1] != nil {
		t.Error("bad-ip result should be nil")
	}
	if results[2] == nil {
		t.Error("third result should succeed")
	}
}
