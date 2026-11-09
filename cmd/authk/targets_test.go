package main

import (
	"reflect"
	"testing"

	"github.com/codozor/authk/internal/config"
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
