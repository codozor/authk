package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

func TestDecodeSegment(t *testing.T) {
	data := map[string]interface{}{"foo": "bar"}
	jsonData, _ := json.Marshal(data)
	encoded := base64.RawURLEncoding.EncodeToString(jsonData)

	decoded, err := decodeSegment(encoded)
	if err != nil {
		t.Fatalf("decodeSegment failed: %v", err)
	}

	asMap, ok := decoded.(map[string]interface{})
	if !ok {
		t.Fatalf("decoded value should be a map, got %T", decoded)
	}

	if asMap["foo"] != "bar" {
		t.Errorf("expected foo=bar, got %v", asMap["foo"])
	}
}

func TestPrintJSON(t *testing.T) {
	// Mock stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Create a sample JSON with timestamps
	// exp: 1733065200 -> 2024-12-01 15:00:00 UTC
	data := map[string]interface{}{
		"exp": 1733065200,
		"iat": 1733061600,
		"sub": "test-user",
	}
	jsonData, _ := json.Marshal(data)
	// Base64 encode it
	encoded := base64.RawURLEncoding.EncodeToString(jsonData)

	printJSON("Test", encoded)

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Log output for debugging if needed
	t.Logf("Output:\n%s", output)

	if !strings.Contains(output, "\"exp\"") {
		t.Errorf("Output should contain 'exp'")
	}

	// Check for readable date format presence
	// We look for the format " (YYYY-MM-DD HH:MM:SS MST)"
	if !strings.Contains(output, "(") || !strings.Contains(output, ")") {
		t.Errorf("Output should contain readable date in parenthesis. Got:\n%s", output)
	}

	// Check year
	if !strings.Contains(output, "2024") {
		t.Errorf("Output should contain the year 2024. Got:\n%s", output)
	}
}
