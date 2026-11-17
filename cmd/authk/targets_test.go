package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/codozor/authk/internal/config"
	"golang.org/x/oauth2"
)

func TestResolveTargets(t *testing.T) {
	old := envFile
	t.Cleanup(func() { envFile = old })
	envFile = "/project/.env"

	p := &config.Profile{Targets: []config.Target{
		{File: "/project/front/.env", Key: "A", Type: config.TargetAccessToken},
		{Key: "B", Type: config.TargetIDToken},
	}}
	want := []config.Target{
		{File: "/project/front/.env", Key: "A", Type: config.TargetAccessToken},
		{File: "/project/.env", Key: "B", Type: config.TargetIDToken},
	}
	if got := resolveTargets(p); !reflect.DeepEqual(got, want) {
		t.Errorf("resolveTargets() = %+v, want %+v", got, want)
	}
	if p.Targets[1].File != "" {
		t.Error("resolveTargets must not modify the profile")
	}
	if got := resolveTargets(&config.Profile{}); len(got) != 0 {
		t.Errorf("a profile without targets must give no target, got %+v", got)
	}
}

func TestUpdateTargets_Formats(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	rawPath := filepath.Join(dir, "secrets", "sa", "token") // directories created
	targets := []config.Target{
		{Format: config.FormatEnv, File: envPath, Key: "TOKEN", Type: config.TargetAccessToken},
		{Format: config.FormatRaw, File: rawPath, Type: config.TargetAccessToken},
	}
	updateTargets(targets, &oauth2.Token{AccessToken: "jwt"})

	if data, err := os.ReadFile(envPath); err != nil || string(data) != "TOKEN=\"jwt\"\n" {
		t.Errorf(".env = %q, %v", data, err)
	}
	if data, err := os.ReadFile(rawPath); err != nil || string(data) != "jwt" {
		t.Errorf("raw file = %q, %v", data, err)
	}

	if got := describeTarget(targets[1]); got != rawPath+" (access_token, raw)" {
		t.Errorf("describeTarget(raw) = %q", got)
	}
	if got := describeTarget(targets[0]); got != envPath+" (access_token → TOKEN)" {
		t.Errorf("describeTarget(env) = %q", got)
	}
}
