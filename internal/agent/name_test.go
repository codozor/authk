package agent

import (
	"path/filepath"
	"testing"
)

func TestName(t *testing.T) {
	p := filepath.FromSlash
	home := p("/home/u")
	tests := []struct {
		config, profile, env, want string
	}{
		{"/home/u/dev/app/authk.cue", "dev", "", "app/dev"},
		{"/home/u/dev/app/authk.cue", "default", "", "app"},
		{"/home/u/dev/app/authk.cue", "", "", "app"},
		// .env next to the config: no suffix
		{"/home/u/dev/app/authk.cue", "default", "/home/u/dev/app/.env", "app"},
		// One agent per project .env
		{"/home/u/dev/legacy/authk.cue", "default", "/home/u/dev/legacy/front/.env", "legacy@front"},
		{"/home/u/dev/legacy/authk.cue", "me", "/home/u/dev/legacy/apps/back/.env", "legacy/me@apps/back"},
		// Global config
		{"/home/u/authk.cue", "default", "/home/u/dev/project/.env", "~@dev/project"},
		{"/home/u/authk.cue", "work", "", "~/work"},
		// .env outside the config directory
		{"/home/u/dev/app/authk.cue", "default", "/srv/shared/.env", "app@shared"},
	}
	for _, tt := range tests {
		env := tt.env
		if env != "" {
			env = p(env)
		}
		if got := Name(p(tt.config), tt.profile, env, home); got != tt.want {
			t.Errorf("Name(%s, %s, %s) = %s, want %s", tt.config, tt.profile, tt.env, got, tt.want)
		}
	}
}
