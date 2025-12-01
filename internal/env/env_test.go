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

func TestManager_Get(t *testing.T) {
	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, ".env")
	err := os.WriteFile(envFile, []byte("KEY=VALUE\n"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	m := NewManager(envFile, "KEY")
	val, err := m.Get()
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if val != "VALUE" {
		t.Errorf("Get() = %s, want VALUE", val)
	}

	m2 := NewManager(envFile, "MISSING")
	_, err = m2.Get()
	if err == nil {
		t.Error("Get() expected error for missing key, got nil")
	}
}

func TestFind(t *testing.T) {
	tmpDir := t.TempDir()
	subdir := filepath.Join(tmpDir, "subdir")
	if err := os.Mkdir(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	envFile := filepath.Join(tmpDir, ".env")
	if err := os.WriteFile(envFile, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	// Test finding from subdir
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()
	if err := os.Chdir(subdir); err != nil {
		t.Fatal(err)
	}

	found, err := Find(".env")
	if err != nil {
		t.Fatalf("Find() error = %v", err)
	}
	if found != envFile {
		t.Errorf("Find() = %s, want %s", found, envFile)
	}
}

func TestFind_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	wd, _ := os.Getwd()
	defer func() { _ = os.Chdir(wd) }()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}

	// Ensure the file doesn't exist in tmpDir or parents (unlikely but possible if running in root)
	// And strictly speaking, we should ensure it's not in home dir either for the fallback.
	// But a random name is safe enough.
	_, err := Find("non_existent_file_random_12345")
	if err == nil {
		t.Error("Find() expected error for non-existent file, got nil")
	}
}

func TestFind_WithSeparator(t *testing.T) {
	// On Linux, this is an absolute path
	path := "/tmp/foo/.env"
	found, err := Find(path)
	if err != nil {
		t.Fatal(err)
	}
	if found != path {
		t.Errorf("Find() = %s, want %s", found, path)
	}
}
