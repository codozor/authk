package env

import (
	"bufio"
	"fmt"
	"os"
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
