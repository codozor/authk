package main

import (
	"encoding/base64"
	"testing"

	"golang.org/x/oauth2"
)

func TestTokenUser(t *testing.T) {
	idToken := func(payload string) *oauth2.Token {
		raw := "e30." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".sig"
		return (&oauth2.Token{AccessToken: "at"}).WithExtra(map[string]any{"id_token": raw})
	}
	tests := map[string]struct {
		token *oauth2.Token
		want  string
	}{
		"username":    {idToken(`{"sub":"123","email":"a@b.c","preferred_username":"alice"}`), "alice"},
		"email":       {idToken(`{"sub":"123","email":"a@b.c"}`), "a@b.c"},
		"subject":     {idToken(`{"sub":"123"}`), "123"},
		"no id token": {&oauth2.Token{AccessToken: "at"}, ""},
		"not a JWT":   {(&oauth2.Token{}).WithExtra(map[string]any{"id_token": "opaque"}), ""},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := tokenUser(tt.token); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
