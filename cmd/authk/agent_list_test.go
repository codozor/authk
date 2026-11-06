package main

import (
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestWithoutDetachFlag(t *testing.T) {
	got := withoutDetachFlag([]string{"agent", "--detach", "--config", "x.cue", "-d", "--detach=true", "--debug"})
	want := []string{"agent", "--config", "x.cue", "--debug"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestTildePath(t *testing.T) {
	home := filepath.FromSlash("/home/u")
	if got := tildePath(filepath.FromSlash("/home/u/dev/authk.cue"), home); got != filepath.FromSlash("~/dev/authk.cue") {
		t.Errorf("got %s", got)
	}
	if got := tildePath(filepath.FromSlash("/etc/authk.cue"), home); got != filepath.FromSlash("/etc/authk.cue") {
		t.Errorf("got %s", got)
	}
}

func TestShortExpiry(t *testing.T) {
	if got := shortExpiry(time.Time{}); got != "no expiry" {
		t.Errorf("got %s", got)
	}
	if got := shortExpiry(time.Now().Add(-time.Second)); got != "EXPIRED" {
		t.Errorf("got %s", got)
	}
	if got := shortExpiry(time.Now().Add(90*time.Second + 400*time.Millisecond)); got != "1m30s" {
		t.Errorf("got %s", got)
	}
}
