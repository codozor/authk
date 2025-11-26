package env

import (
	"bufio"
	"fmt"
	"os"
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

	// Prepare the new line content
	// We assume simple KEY=VALUE format.
	// If value contains spaces or special chars, we might need quoting.
	// For tokens, it's usually safe, but let's quote it to be safe.
	newLine := fmt.Sprintf("%s=\"%s\"", m.key, value)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, m.key+"=") || strings.HasPrefix(trimmed, "export "+m.key+"=") {
			newLines = append(newLines, newLine)
			found = true
		} else {
			newLines = append(newLines, line)
		}
	}

	if !found {
		newLines = append(newLines, newLine)
	}

	return m.writeLines(newLines)
}

func (m *Manager) readLines() ([]string, error) {
	file, err := os.Open(m.filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func (m *Manager) writeLines(lines []string) error {
	file, err := os.Create(m.filePath)
	if err != nil {
		return fmt.Errorf("failed to create/open .env file: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range lines {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return err
		}
	}
	return writer.Flush()
}
