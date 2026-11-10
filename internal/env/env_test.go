package env

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
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
				if err := os.WriteFile(envFile, []byte(tt.initial), 0o644); err != nil {
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
	err := os.WriteFile(envFile, []byte("KEY=VALUE\n"), 0o644)
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
	if err := os.Mkdir(subdir, 0o755); err != nil {
		t.Fatal(err)
	}

	envFile := filepath.Join(tmpDir, ".env")
	if err := os.WriteFile(envFile, []byte(""), 0o644); err != nil {
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

func TestManager_Update_Permissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	dir := t.TempDir()

	// A new file holds a token: it must not be readable by others
	newFile := filepath.Join(dir, ".env")
	if err := NewManager(newFile, "TOKEN").Update("v1"); err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	info, err := os.Stat(newFile)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("new file mode = %o, want 600", got)
	}

	// An existing file keeps its permissions
	existing := filepath.Join(dir, ".env.shared")
	if err := os.WriteFile(existing, []byte("OTHER=1\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(existing, 0o640); err != nil { // bypass umask
		t.Fatal(err)
	}
	if err := NewManager(existing, "TOKEN").Update("v1"); err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	info, err = os.Stat(existing)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Errorf("existing file mode = %o, want 640", got)
	}

	// No temporary file is left behind
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("expected only the 2 .env files, got %v", names)
	}
}

func TestManager_Update_Symlink(t *testing.T) {
	dir := t.TempDir()
	realFile := filepath.Join(dir, "real.env")
	link := filepath.Join(dir, ".env")
	if err := os.WriteFile(realFile, []byte("TOKEN=old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realFile, link); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}

	if err := NewManager(link, "TOKEN").Update("new"); err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Error("the symlink was replaced by a regular file")
	}
	content, err := os.ReadFile(realFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "TOKEN=\"new\"\n" {
		t.Errorf("target file content = %q", content)
	}
}

func TestResolveEnvFile(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	project := filepath.Join(home, "dev", "project")
	sub := filepath.Join(project, "src", "pkg")
	other := filepath.Join(home, "dev", "other")
	for _, d := range []string{sub, other} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	touch := func(p string) {
		t.Helper()
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	projectConfig := filepath.Join(project, "authk.cue")
	globalConfig := filepath.Join(home, "authk.cue")
	// Never used: the home directory is not searched
	touch(filepath.Join(home, ".env"))
	// Above the project: never used for a project config
	touch(filepath.Join(home, "dev", ".env"))

	tests := []struct {
		name, env, config, cwd, want string
		setup                        func()
	}{
		{name: "project, no .env: next to the config", env: ".env", config: projectConfig, cwd: sub,
			want: filepath.Join(project, ".env")},
		{name: "project, cwd outside: next to the config", env: ".env", config: projectConfig, cwd: other,
			want: filepath.Join(project, ".env")},
		{name: "explicit path is made absolute", env: "front/.env", config: projectConfig, cwd: project,
			want: filepath.Join(project, "front", ".env")},
		{name: "project, nearest .env in a subdirectory", env: ".env", config: projectConfig, cwd: sub,
			setup: func() { touch(filepath.Join(project, "src", ".env")) },
			want:  filepath.Join(project, "src", ".env")},
		{name: "global config, no .env: in cwd, not ~/.env nor ~/dev/.env", env: ".env.local", config: globalConfig, cwd: other,
			want: filepath.Join(other, ".env.local")},
		{name: "global config, .env found in a parent below home", env: ".env", config: globalConfig, cwd: other,
			want: filepath.Join(home, "dev", ".env")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}
			got, err := ResolveEnvFile(tt.env, tt.config, tt.cwd, home)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestManager_Update_MissingDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", ".env")
	err := NewManager(path, "TOKEN").Update("v")
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("expected a missing directory error, got %v", err)
	}
}
