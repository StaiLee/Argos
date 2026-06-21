package config

import (
	"reflect"
	"testing"
)

func TestParseTargetsSingleIP(t *testing.T) {
	got, err := ParseTargets("10.0.0.5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := []string{"10.0.0.5"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseTargetsCIDRExcludesNetworkAndBroadcast(t *testing.T) {
	got, err := ParseTargets("192.168.1.0/30")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"192.168.1.1", "192.168.1.2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseTargetsCIDRHostCount(t *testing.T) {
	// /29 = 8 addresses, minus network + broadcast = 6 usable hosts.
	got, err := ParseTargets("10.0.0.0/29")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 6 {
		t.Fatalf("expected 6 hosts, got %d (%v)", len(got), got)
	}
}

func TestParseTargetsIPv6CIDRUnsupported(t *testing.T) {
	if _, err := ParseTargets("2001:db8::/64"); err == nil {
		t.Fatal("expected an error for an IPv6 CIDR (not yet supported)")
	}
}

func TestParseTargetsInvalidCIDR(t *testing.T) {
	if _, err := ParseTargets("10.0.0.0/33"); err == nil {
		t.Fatal("expected an error for an invalid CIDR mask")
	}
}

func TestParseTargetsUnresolvableDomain(t *testing.T) {
	if _, err := ParseTargets("nonexistent-host.invalid"); err == nil {
		t.Fatal("expected an error for an unresolvable domain")
	}
}

func TestParsePortsSingle(t *testing.T) {
	got, err := ParsePorts("80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := []int{80}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParsePortsListAndRange(t *testing.T) {
	got, err := ParsePorts("22,80-82,443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []int{22, 80, 81, 82, 443}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParsePortsAll(t *testing.T) {
	got, err := ParsePorts("all")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 65535 {
		t.Fatalf("expected 65535 ports, got %d", len(got))
	}
	if got[0] != 1 || got[len(got)-1] != 65535 {
		t.Fatalf("range bounds wrong: first=%d last=%d", got[0], got[len(got)-1])
	}
}
