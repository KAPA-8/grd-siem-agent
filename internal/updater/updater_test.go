package updater

import (
	"testing"
)

func TestParseChecksum(t *testing.T) {
	data := `abc123def456789012345678901234567890123456789012345678901234  grd-siem-agent-linux-amd64
fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210  grd-siem-agent-windows-amd64.exe
1111111111111111111111111111111111111111111111111111111111111111  grd-siem-agent-darwin-arm64
`
	tests := []struct {
		filename string
		wantHash string
		wantErr  bool
	}{
		{"grd-siem-agent-linux-amd64", "abc123def456789012345678901234567890123456789012345678901234", false},
		{"grd-siem-agent-windows-amd64.exe", "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", false},
		{"grd-siem-agent-darwin-arm64", "1111111111111111111111111111111111111111111111111111111111111111", false},
		{"nonexistent", "", true},
	}

	for _, tt := range tests {
		hash, err := ParseChecksum(data, tt.filename)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseChecksum(%q): expected error, got nil", tt.filename)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseChecksum(%q): unexpected error: %v", tt.filename, err)
			continue
		}
		if hash != tt.wantHash {
			t.Errorf("ParseChecksum(%q) = %q, want %q", tt.filename, hash, tt.wantHash)
		}
	}
}

func TestParseChecksumEmptyInput(t *testing.T) {
	_, err := ParseChecksum("", "anything")
	if err == nil {
		t.Error("expected error for empty checksums data")
	}
}

func TestBinaryAssetName(t *testing.T) {
	name := BinaryAssetName()
	if name == "" {
		t.Fatal("expected non-empty asset name")
	}
	// Should always start with grd-siem-agent-
	if !contains(name, "grd-siem-agent-") {
		t.Errorf("asset name %q does not start with expected prefix", name)
	}
}

func TestEnsureVPrefix(t *testing.T) {
	tests := []struct {
		input, expected string
	}{
		{"v1.0.0", "v1.0.0"},
		{"1.0.0", "v1.0.0"},
		{"v0.1.0-rc.1", "v0.1.0-rc.1"},
		{"0.1.0-beta.2", "v0.1.0-beta.2"},
		{"v2.3.4+build.123", "v2.3.4+build.123"},
	}
	for _, tt := range tests {
		got := EnsureVPrefix(tt.input)
		if got != tt.expected {
			t.Errorf("EnsureVPrefix(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s[:len(substr)] == substr || containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
