package env

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Manager struct {
	filePath string
	key      string
}

func NewManager(filePath, key string) *Manager {
	return &Manager{
		filePath: filePath,
		key:      key,
	}
}

func (m *Manager) Update(value string) error {
	lines, err := m.readLines()
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read .env file: %w", err)
	}

	found := false
	newLines := make([]string, 0, len(lines)+1)

	// Regex to match:
	// Group 1: Leading whitespace
	// Group 2: Optional "export "
	// Group 3: Key
	// Group 4: Equals sign with optional surrounding whitespace
	// Group 5: The rest of the line (value + comment)
	regexStr := fmt.Sprintf(`^(\s*)(export\s+)?(%s)(\s*=\s*)(.*)$`, regexp.QuoteMeta(m.key))
	re := regexp.MustCompile(regexStr)

	for _, line := range lines {
		matches := re.FindStringSubmatch(line)
		if matches != nil {
			indent := matches[1]
			export := matches[2]
			// key := matches[3] // We know it matches m.key
			equals := matches[4]
			rest := matches[5]

			// Try to preserve comment
			comment := ""
			// Simple heuristic: look for " #"
			if idx := strings.Index(rest, " #"); idx != -1 {
				comment = rest[idx:]
			}

			// Construct new line
			// We always quote the new value for safety
			newLine := fmt.Sprintf("%s%s%s%s\"%s\"%s", indent, export, m.key, equals, value, comment)
			newLines = append(newLines, newLine)
			found = true
		} else {
			newLines = append(newLines, line)
		}
	}

	if !found {
		// Append new key
		newLines = append(newLines, fmt.Sprintf("%s=\"%s\"", m.key, value))
	}

	return m.writeLines(newLines)
}

func (m *Manager) Get() (string, error) {
	lines, err := m.readLines()
	if err != nil {
		return "", err
	}

	regexStr := fmt.Sprintf(`^(\s*)(export\s+)?(%s)(\s*=\s*)(.*)$`, regexp.QuoteMeta(m.key))
	re := regexp.MustCompile(regexStr)

	for _, line := range lines {
		matches := re.FindStringSubmatch(line)
		if matches != nil {
			valuePart := matches[5]

			// Remove comment if present
			if idx := strings.Index(valuePart, " #"); idx != -1 {
				valuePart = valuePart[:idx]
			}

			value := strings.TrimSpace(valuePart)

			// Remove surrounding quotes if present
			if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
				value = value[1 : len(value)-1]
			} else if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
				value = value[1 : len(value)-1]
			}

			return value, nil
		}
	}
	return "", fmt.Errorf("key %s not found in .env file", m.key)
}

func (m *Manager) readLines() ([]string, error) {
	file, err := os.Open(m.filePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// newFileMode is the permission of a .env file created by authk: it holds a token.
const newFileMode os.FileMode = 0o600

// writeLines replaces the file atomically (temp file + rename) so that readers never
// see a truncated file. An existing file keeps its permissions; a new one gets 0600.
// A symlink is followed, so the link itself is preserved.
func (m *Manager) writeLines(lines []string) error {
	path := m.filePath
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}

	mode := newFileMode
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}

	if info, err := os.Stat(filepath.Dir(path)); err != nil || !info.IsDir() {
		return fmt.Errorf("directory %s does not exist", filepath.Dir(path))
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".authk-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary .env file: %w", err)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	writer := bufio.NewWriter(tmp)
	for _, line := range lines {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		return fmt.Errorf("failed to set .env file permissions: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("failed to replace .env file: %w", err)
	}
	committed = true
	return nil
}

// Find searches for the given filename in the current directory and parent directories.
// If found, it returns the absolute path.
// If not found, it returns an error.
func Find(name string) (string, error) {
	// If name contains path separator, return it as is (cleaned)
	if strings.Contains(name, string(os.PathSeparator)) {
		return filepath.Clean(name), nil
	}

	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break // Reached root
		}
		dir = parent
	}

	// Fallback: Check home directory
	home, err := os.UserHomeDir()
	if err == nil {
		path := filepath.Join(home, name)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("%s not found", name)
}

// ResolveEnvFile returns the absolute path of the .env file to use with the config file
// configPath, searching from the directory cwd. name is the --env value.
//
//   - A name with a directory part is used as is, relative to cwd.
//   - Project config (outside the home directory root): the file is searched from cwd up
//     to the config directory, never above; if not found, it goes next to the config.
//   - Global config (in the home directory root): the file is searched from cwd up to,
//     but excluding, the home directory; if not found, it goes in cwd.
//
// The home directory itself is never searched: a project without .env must not write
// its token to ~/.env, nor share it with every other project.
func ResolveEnvFile(name, configPath, cwd, home string) (string, error) {
	if filepath.IsAbs(name) {
		return filepath.Clean(name), nil
	}
	if strings.ContainsRune(name, os.PathSeparator) || strings.ContainsRune(name, '/') {
		return filepath.Join(cwd, name), nil
	}

	absConfig, err := filepath.Abs(configPath)
	if err != nil {
		return "", err
	}
	configDir := filepath.Dir(absConfig)
	cwd = filepath.Clean(cwd)
	home = filepath.Clean(home)

	if home == "" || home == "." || configDir != home {
		// Project config
		if isWithin(cwd, configDir) {
			if found, ok := searchUp(name, cwd, configDir, true); ok {
				return found, nil
			}
		}
		return filepath.Join(configDir, name), nil
	}

	// Global config
	if found, ok := searchUp(name, cwd, home, false); ok {
		return found, nil
	}
	return filepath.Join(cwd, name), nil
}

// searchUp looks for name from dir up to stop (included if inclusive), or up to the
// filesystem root if dir is not within stop.
func searchUp(name, dir, stop string, inclusive bool) (string, bool) {
	bounded := isWithin(dir, stop)
	for {
		if bounded && dir == stop && !inclusive {
			return "", false
		}
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path, true
		}
		if bounded && dir == stop {
			return "", false
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// isWithin reports whether path is dir or one of its subdirectories.
func isWithin(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}
