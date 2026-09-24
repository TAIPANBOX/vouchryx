package xaa

import (
	"errors"
	"testing"
)

func TestResourcesAreParsedFromACommaSeparatedList(t *testing.T) {
	got, err := ParseResources("https://a.example/mcp,https://b.example/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "https://a.example/mcp" || got[1] != "https://b.example/mcp" {
		t.Fatalf("got %v", got)
	}
}

func TestANonAbsoluteURLInResourcesIsRefused(t *testing.T) {
	for _, bad := range []string{"not-a-url", "//no-scheme.example", "https://"} {
		if _, err := ParseResources(bad); err == nil {
			t.Fatalf("resource %q was accepted", bad)
		}
	}
}

func TestSelectResourceWhenOnlyTheAssertionNamesOne(t *testing.T) {
	got, err := SelectResource("https://a.example/mcp", "", []string{"https://a.example/mcp"})
	if err != nil || got != "https://a.example/mcp" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestSelectResourceWhenOnlyTheRequestNamesOne(t *testing.T) {
	got, err := SelectResource("", "https://a.example/mcp", []string{"https://a.example/mcp"})
	if err != nil || got != "https://a.example/mcp" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestSelectResourceWhenNeitherNamesOneAndExactlyOneIsConfigured(t *testing.T) {
	got, err := SelectResource("", "", []string{"https://a.example/mcp"})
	if err != nil || got != "https://a.example/mcp" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestSelectResourceWhenNeitherNamesOneAndSeveralAreConfigured(t *testing.T) {
	_, err := SelectResource("", "", []string{"https://a.example/mcp", "https://b.example/mcp"})
	if !errors.Is(err, ErrResourceAmbiguous) {
		t.Fatalf("got %v, want ErrResourceAmbiguous", err)
	}
}

func TestAResourceOutsideTheConfiguredSetIsRefusedAtSelection(t *testing.T) {
	_, err := SelectResource("https://evil.example/mcp", "", []string{"https://a.example/mcp"})
	if !errors.Is(err, ErrResourceNotConfigured) {
		t.Fatalf("got %v, want ErrResourceNotConfigured", err)
	}
}

func TestWhenBothNameAResourceTheyMustAgree(t *testing.T) {
	_, err := SelectResource("https://a.example/mcp", "https://b.example/mcp", []string{"https://a.example/mcp", "https://b.example/mcp"})
	if !errors.Is(err, ErrResourceMismatch) {
		t.Fatalf("got %v, want ErrResourceMismatch", err)
	}
	got, err := SelectResource("https://a.example/mcp", "https://a.example/mcp", []string{"https://a.example/mcp"})
	if err != nil || got != "https://a.example/mcp" {
		t.Fatalf("agreeing resources were refused: %q, %v", got, err)
	}
}
