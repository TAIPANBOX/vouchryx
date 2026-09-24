package xaa

import (
	"errors"
	"testing"
)

func TestNarrowScopeInheritsWhenTheRequestAsksForNone(t *testing.T) {
	got, err := NarrowScope("read write", "")
	if err != nil || got != "read write" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestNarrowScopeAcceptsASubset(t *testing.T) {
	got, err := NarrowScope("read write", "read")
	if err != nil || got != "read" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestNarrowScopeRefusesASuperset(t *testing.T) {
	_, err := NarrowScope("read", "read write")
	if !errors.Is(err, ErrScopeWidened) {
		t.Fatalf("got %v, want ErrScopeWidened", err)
	}
}

func TestNarrowScopeRefusesAnythingWhenTheAssertionHoldsNone(t *testing.T) {
	_, err := NarrowScope("", "read")
	if !errors.Is(err, ErrScopeWidened) {
		t.Fatalf("got %v, want ErrScopeWidened", err)
	}
}

func TestNarrowScopeWithNeitherSideHoldingAnyIsEmpty(t *testing.T) {
	got, err := NarrowScope("", "")
	if err != nil || got != "" {
		t.Fatalf("got %q, %v", got, err)
	}
}
