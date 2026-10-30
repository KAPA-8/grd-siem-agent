package mitre

import "testing"

func TestExtract_TCodeInDescription(t *testing.T) {
	result := Extract("Detected T1059.001 PowerShell execution", nil)
	if result.TechniqueID != "T1059.001" {
		t.Errorf("TechniqueID = %q, want T1059.001", result.TechniqueID)
	}
}

func TestExtract_CategoryMatch(t *testing.T) {
	tests := []struct {
		categories []string
		wantID     string
		wantTactic string
	}{
		{[]string{"Authentication"}, "T1110", "credential_access"},
		{[]string{"Malware"}, "T1204", "execution"},
		{[]string{"Denial of Service"}, "T1498", "impact"},
		{[]string{"Reconnaissance"}, "T1595", "reconnaissance"},
		{[]string{"Ransomware"}, "T1486", "impact"},
		{[]string{"Data Exfiltration"}, "T1041", "exfiltration"},
	}

	for _, tt := range tests {
		result := Extract("generic offense", tt.categories)
		if result.TechniqueID != tt.wantID {
			t.Errorf("categories=%v: TechniqueID = %q, want %q", tt.categories, result.TechniqueID, tt.wantID)
		}
		if result.Tactic != tt.wantTactic {
			t.Errorf("categories=%v: Tactic = %q, want %q", tt.categories, result.Tactic, tt.wantTactic)
		}
	}
}

func TestExtract_KeywordInDescription(t *testing.T) {
	tests := []struct {
		description string
		wantID      string
	}{
		{"Multiple brute force attempts detected", "T1110"},
		{"Phishing email with malicious attachment", "T1566"},
		{"Lateral movement detected via RDP", "T1021"},
		{"Privilege escalation attempt", "T1068"},
	}

	for _, tt := range tests {
		result := Extract(tt.description, nil)
		if result.TechniqueID != tt.wantID {
			t.Errorf("desc=%q: TechniqueID = %q, want %q", tt.description, result.TechniqueID, tt.wantID)
		}
	}
}

func TestExtract_DefaultFallback(t *testing.T) {
	result := Extract("Something completely unrelated", []string{"CustomCategory"})
	if result.TechniqueID != "T1059" {
		t.Errorf("expected default T1059 for unmatched input, got %q", result.TechniqueID)
	}
	if result.TechniqueName != "Command and Scripting Interpreter" {
		t.Errorf("expected default technique name, got %q", result.TechniqueName)
	}
}

func TestExtract_SpanishKeywords(t *testing.T) {
	tests := []struct {
		description string
		wantID      string
	}{
		{"Desinstalación de software no autorizado", "T1562"},
		{"Inicio de sesión fallido desde IP externa", "T1110"},
		{"Actividad sospechosa en el servidor", "T1059"},
		{"Fuerza bruta detectada en el firewall", "T1110"},
	}

	for _, tt := range tests {
		result := Extract(tt.description, nil)
		if result.TechniqueID != tt.wantID {
			t.Errorf("desc=%q: TechniqueID = %q, want %q", tt.description, result.TechniqueID, tt.wantID)
		}
	}
}
