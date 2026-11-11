package main

import (
	"reflect"
	"testing"

	"github.com/codozor/authk/internal/agent"
	"github.com/codozor/authk/internal/config"
)

func TestParseVarFlags(t *testing.T) {
	vars, err := parseVarFlags([]string{"TOKEN", "ID=id_token", "AT=access_token", "TOKEN"})
	if err != nil {
		t.Fatal(err)
	}
	want := []execVar{
		{Name: "TOKEN", Type: agent.TypeAccessToken},
		{Name: "ID", Type: agent.TypeIDToken},
		{Name: "AT", Type: agent.TypeAccessToken},
	}
	if !reflect.DeepEqual(vars, want) {
		t.Errorf("got %+v, want %+v", vars, want)
	}

	for _, bad := range [][]string{
		{"1TOKEN"},
		{"MY-TOKEN"},
		{"TOKEN=refresh_token"},
		{"TOKEN", "TOKEN=id_token"},
		{"=id_token"},
	} {
		if _, err := parseVarFlags(bad); err == nil {
			t.Errorf("%v: expected an error", bad)
		}
	}
}

func TestTargetVars(t *testing.T) {
	vars, err := targetVars([]config.Target{
		{Key: "TOKEN", Type: agent.TypeAccessToken},
		{File: "/a/.env", Key: "TOKEN", Type: agent.TypeAccessToken},
		{Key: "ID_TOKEN", Type: agent.TypeIDToken},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []execVar{{Name: "TOKEN", Type: agent.TypeAccessToken}, {Name: "ID_TOKEN", Type: agent.TypeIDToken}}
	if !reflect.DeepEqual(vars, want) {
		t.Errorf("got %+v, want %+v", vars, want)
	}

	vars, err = targetVars(nil)
	if err != nil {
		t.Fatal(err)
	}
	want = []execVar{
		{Name: "ACCESS_TOKEN", Type: agent.TypeAccessToken},
		{Name: "ID_TOKEN", Type: agent.TypeIDToken, Optional: true},
	}
	if !reflect.DeepEqual(vars, want) {
		t.Errorf("without targets: got %+v, want %+v", vars, want)
	}

	if _, err := targetVars([]config.Target{
		{Key: "TOKEN", Type: agent.TypeAccessToken},
		{File: "/a/.env", Key: "TOKEN", Type: agent.TypeIDToken},
	}); err == nil {
		t.Error("expected an error for a key with two token types")
	}
}

func TestVarTypes(t *testing.T) {
	types, idOptional := varTypes([]execVar{
		{Name: "ACCESS_TOKEN", Type: agent.TypeAccessToken},
		{Name: "ID_TOKEN", Type: agent.TypeIDToken, Optional: true},
	})
	if !reflect.DeepEqual(types, []string{agent.TypeAccessToken, agent.TypeIDToken}) || !idOptional {
		t.Errorf("got %v, %t", types, idOptional)
	}
	_, idOptional = varTypes([]execVar{
		{Name: "A", Type: agent.TypeIDToken, Optional: true},
		{Name: "B", Type: agent.TypeIDToken},
	})
	if idOptional {
		t.Error("a required ID Token variable must make the ID Token required")
	}
}

func TestSetEnv(t *testing.T) {
	env := setEnv([]string{"PATH=/bin", "TOKEN=old", "TOKEN_X=keep"}, "TOKEN", "new")
	want := []string{"PATH=/bin", "TOKEN_X=keep", "TOKEN=new"}
	if !reflect.DeepEqual(env, want) {
		t.Errorf("got %v, want %v", env, want)
	}
}

func TestExitCode(t *testing.T) {
	if code, ok := exitCode(&exitError{code: 3}); !ok || code != 3 {
		t.Errorf("got %d, %t", code, ok)
	}
	if _, ok := exitCode(agent.ErrNoIDToken); ok {
		t.Error("an authk error is not an exit code")
	}
}
