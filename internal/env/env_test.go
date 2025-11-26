package env

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManager_Update(t *testing.T) {
	tests := []struct {
		name     string
		initial  string
		key      string
		value    string
		expected string
	}{
		{
			name:     "Simple update",
			initial:  "KEY=old",
			key:      "KEY",
			value:    "new",
			expected: "KEY=\"new\"\n",
		},
		{
			name:     "Export prefix",
			initial:  "export KEY=old",
			key:      "KEY",
			value:    "new",
			expected: "export KEY=\"new\"\n",
		},
		{
			name:     "Spaces around equals",
			initial:  "KEY = old",
			key:      "KEY",
			value:    "new",
			expected: "KEY = \"new\"\n",
		},
		{
			name:     "Preserve comments",
			initial:  "KEY=old # my comment",
			key:      "KEY",
			value:    "new",
			expected: "KEY=\"new\" # my comment\n",
		},
		{
			name:     "Preserve surrounding lines",
			initial:  "OTHER=foo\nKEY=old\nANOTHER=bar",
			key:      "KEY",
			value:    "new",
			expected: "OTHER=foo\nKEY=\"new\"\nANOTHER=bar\n",
		},
		{
			name:     "Create if not exists",
			initial:  "",
			key:      "KEY",
			value:    "new",
			expected: "KEY=\"new\"\n",
		},
		{
			name:     "Append if not found",
			initial:  "OTHER=foo",
			key:      "KEY",
			value:    "new",
			expected: "OTHER=foo\nKEY=\"new\"\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			envFile := filepath.Join(tmpDir, ".env")

			if tt.initial != "" {
				if err := os.WriteFile(envFile, []byte(tt.initial), 0644); err != nil {
					t.Fatalf("failed to create initial .env: %v", err)
				}
			}

			mgr := NewManager(envFile, tt.key)
			if err := mgr.Update(tt.value); err != nil {
				t.Fatalf("Update() error = %v", err)
			}

			content, err := os.ReadFile(envFile)
			if err != nil {
				t.Fatalf("failed to read .env: %v", err)
			}

			if string(content) != tt.expected {
				t.Errorf("Update() result mismatch:\ngot:\n%s\nwant:\n%s", string(content), tt.expected)
			}
		})
	}
}
