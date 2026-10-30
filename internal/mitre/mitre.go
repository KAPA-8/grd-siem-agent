// Package mitre holds SIEM-agnostic heuristics that infer a MITRE ATT&CK
// technique from free text (alert descriptions) and SIEM categories. It is
// used for sources that do not carry native ATT&CK data (e.g. QRadar offenses).
package mitre

import (
	"regexp"
	"strings"
)

// MITRE technique patterns extracted from alert descriptions and categories.
// This mirrors the extractMitreFromDescription logic from the platform's qradar-adapter.ts.
var mitreTechniqueRegex = regexp.MustCompile(`T\d{4}(?:\.\d{3})?`)

// categoryToMITRE maps common SIEM (QRadar) categories to MITRE ATT&CK techniques.
// The third value is the ATT&CK tactic in snake_case.
var categoryToMITRE = map[string]struct {
	TechniqueID   string
	TechniqueName string
	Tactic        string
}{
	// Authentication & Credentials
	"Authentication":         {"T1110", "Brute Force", "credential_access"},
	"User Login Failure":     {"T1110", "Brute Force", "credential_access"},
	"User Login Success":     {"T1078", "Valid Accounts", "credential_access"},
	"Suspicious Activity":    {"T1059", "Command and Scripting Interpreter", "execution"},
	"Authentication Failure": {"T1110", "Brute Force", "credential_access"},
	"Credential Theft":       {"T1003", "OS Credential Dumping", "credential_access"},

	// Malware & Exploits
	"Malware":    {"T1204", "User Execution", "execution"},
	"Exploit":    {"T1203", "Exploitation for Client Execution", "execution"},
	"Virus/Worm": {"T1204", "User Execution", "execution"},
	"Trojan":     {"T1204", "User Execution", "execution"},
	"Ransomware": {"T1486", "Data Encrypted for Impact", "impact"},
	"Botnet":     {"T1583", "Acquire Infrastructure", "resource_development"},
	"Spyware":    {"T1005", "Data from Local System", "collection"},

	// Network
	"Denial of Service": {"T1498", "Network Denial of Service", "impact"},
	"DoS":               {"T1498", "Network Denial of Service", "impact"},
	"Reconnaissance":    {"T1595", "Active Scanning", "reconnaissance"},
	"Scan":              {"T1595", "Active Scanning", "reconnaissance"},
	"Port Scan":         {"T1046", "Network Service Discovery", "discovery"},
	"Network Anomaly":   {"T1071", "Application Layer Protocol", "command_and_control"},

	// Policy & Access
	"Policy Violation": {"T1078", "Valid Accounts", "initial_access"},
	"Access Violation": {"T1078", "Valid Accounts", "initial_access"},
	"Anomaly":          {"T1078", "Valid Accounts", "initial_access"},
	"Audit":            {"T1078", "Valid Accounts", "defense_evasion"},
	"Compliance":       {"T1078", "Valid Accounts", "initial_access"},

	// Software & System
	"Software Change": {"T1562", "Impair Defenses", "defense_evasion"},
	"Application":     {"T1059", "Command and Scripting Interpreter", "execution"},
	"System":          {"T1059", "Command and Scripting Interpreter", "execution"},
	"Configuration":   {"T1562", "Impair Defenses", "defense_evasion"},
	"Firewall":        {"T1562.004", "Disable or Modify System Firewall", "defense_evasion"},

	// Data
	"Data Exfiltration": {"T1041", "Exfiltration Over C2 Channel", "exfiltration"},
	"Data Loss":         {"T1567", "Exfiltration Over Web Service", "exfiltration"},
	"Data Destruction":  {"T1485", "Data Destruction", "impact"},

	// Command & Control
	"Command and Control": {"T1071", "Application Layer Protocol", "command_and_control"},
	"C2":                  {"T1071", "Application Layer Protocol", "command_and_control"},
	"CnC":                 {"T1071", "Application Layer Protocol", "command_and_control"},

	// Lateral Movement
	"Lateral Movement": {"T1021", "Remote Services", "lateral_movement"},

	// Privilege Escalation
	"Privilege Escalation": {"T1068", "Exploitation for Privilege Escalation", "privilege_escalation"},
}

// Mapping holds the inferred MITRE technique info. Tactic is the ATT&CK tactic
// in snake_case (e.g. "credential_access"); the platform derives the FAIR
// impact type from it when the technique is not in its catalog.
type Mapping struct {
	TechniqueID   string
	TechniqueName string
	Tactic        string
}

// Extract attempts to infer a MITRE ATT&CK technique from a description and categories.
// Priority: 1) T-code in description text, 2) exact category match, 3) partial category match,
// 4) keyword in description, 5) default fallback (never returns empty).
func Extract(description string, categories []string) Mapping {
	// Try to find T-code directly in the description (e.g., "T1110", "T1059.001")
	if matches := mitreTechniqueRegex.FindStringSubmatch(description); len(matches) > 0 {
		return Mapping{TechniqueID: matches[0]}
	}

	// Try exact category-based mapping
	for _, cat := range categories {
		cat = strings.TrimSpace(cat)
		if mapping, ok := categoryToMITRE[cat]; ok {
			return Mapping{
				TechniqueID:   mapping.TechniqueID,
				TechniqueName: mapping.TechniqueName,
				Tactic:        mapping.Tactic,
			}
		}
	}

	// Try partial matching on categories
	for _, cat := range categories {
		catLower := strings.ToLower(cat)
		for keyword, mapping := range categoryToMITRE {
			if strings.Contains(catLower, strings.ToLower(keyword)) {
				return Mapping{
					TechniqueID:   mapping.TechniqueID,
					TechniqueName: mapping.TechniqueName,
					Tactic:        mapping.Tactic,
				}
			}
		}
	}

	// Try keyword matching in description (English + Spanish)
	descLower := strings.ToLower(description)
	for _, entry := range descriptionKeywords {
		if strings.Contains(descLower, entry.keyword) {
			return entry.mapping
		}
	}

	// Default fallback — always return a technique
	return Mapping{
		TechniqueID:   "T1059",
		TechniqueName: "Command and Scripting Interpreter",
		Tactic:        "execution",
	}
}

// descriptionKeyword pairs a keyword with its MITRE mapping.
type descriptionKeyword struct {
	keyword string
	mapping Mapping
}

// descriptionKeywords maps keywords found in offense descriptions to MITRE techniques.
// Includes both English and Spanish terms common in QRadar deployments.
var descriptionKeywords = []descriptionKeyword{
	// Authentication / Credentials
	{"brute force", Mapping{"T1110", "Brute Force", "credential_access"}},
	{"fuerza bruta", Mapping{"T1110", "Brute Force", "credential_access"}},
	{"failed login", Mapping{"T1110", "Brute Force", "credential_access"}},
	{"login failure", Mapping{"T1110", "Brute Force", "credential_access"}},
	{"inicio de sesión fallido", Mapping{"T1110", "Brute Force", "credential_access"}},
	{"autenticación fallida", Mapping{"T1110", "Brute Force", "credential_access"}},
	{"credential", Mapping{"T1003", "OS Credential Dumping", "credential_access"}},
	{"credencial", Mapping{"T1003", "OS Credential Dumping", "credential_access"}},
	{"password spray", Mapping{"T1110.003", "Password Spraying", "credential_access"}},

	// Malware
	{"malware", Mapping{"T1204", "User Execution", "execution"}},
	{"ransomware", Mapping{"T1486", "Data Encrypted for Impact", "impact"}},
	{"phishing", Mapping{"T1566", "Phishing", "initial_access"}},
	{"trojan", Mapping{"T1204", "User Execution", "execution"}},
	{"troyano", Mapping{"T1204", "User Execution", "execution"}},
	{"virus", Mapping{"T1204", "User Execution", "execution"}},

	// Network / Scanning
	{"scan", Mapping{"T1595", "Active Scanning", "reconnaissance"}},
	{"escaneo", Mapping{"T1595", "Active Scanning", "reconnaissance"}},
	{"denial of service", Mapping{"T1498", "Network Denial of Service", "impact"}},
	{"denegación de servicio", Mapping{"T1498", "Network Denial of Service", "impact"}},
	{"ddos", Mapping{"T1498", "Network Denial of Service", "impact"}},

	// Data
	{"exfiltration", Mapping{"T1041", "Exfiltration Over C2 Channel", "exfiltration"}},
	{"exfiltración", Mapping{"T1041", "Exfiltration Over C2 Channel", "exfiltration"}},
	{"data loss", Mapping{"T1567", "Exfiltration Over Web Service", "exfiltration"}},
	{"pérdida de datos", Mapping{"T1567", "Exfiltration Over Web Service", "exfiltration"}},
	{"destrucción", Mapping{"T1485", "Data Destruction", "impact"}},
	{"destruction", Mapping{"T1485", "Data Destruction", "impact"}},

	// Privilege / Access
	{"privilege", Mapping{"T1068", "Exploitation for Privilege Escalation", "privilege_escalation"}},
	{"privilegio", Mapping{"T1068", "Exploitation for Privilege Escalation", "privilege_escalation"}},
	{"escalation", Mapping{"T1068", "Exploitation for Privilege Escalation", "privilege_escalation"}},
	{"escalamiento", Mapping{"T1068", "Exploitation for Privilege Escalation", "privilege_escalation"}},
	{"lateral", Mapping{"T1021", "Remote Services", "lateral_movement"}},
	{"unauthorized access", Mapping{"T1078", "Valid Accounts", "initial_access"}},
	{"acceso no autorizado", Mapping{"T1078", "Valid Accounts", "initial_access"}},

	// Software / System changes
	{"uninstall", Mapping{"T1562", "Impair Defenses", "defense_evasion"}},
	{"desinstalación", Mapping{"T1562", "Impair Defenses", "defense_evasion"}},
	{"desinstalar", Mapping{"T1562", "Impair Defenses", "defense_evasion"}},
	{"software no autorizado", Mapping{"T1562", "Impair Defenses", "defense_evasion"}},
	{"unauthorized software", Mapping{"T1562", "Impair Defenses", "defense_evasion"}},
	{"instalación no autorizada", Mapping{"T1072", "Software Deployment Tools", "execution"}},
	{"unauthorized install", Mapping{"T1072", "Software Deployment Tools", "execution"}},
	{"disabled", Mapping{"T1562", "Impair Defenses", "defense_evasion"}},
	{"deshabilitado", Mapping{"T1562", "Impair Defenses", "defense_evasion"}},
	{"firewall", Mapping{"T1562.004", "Disable or Modify System Firewall", "defense_evasion"}},
	{"antivirus", Mapping{"T1562.001", "Disable or Modify Tools", "defense_evasion"}},

	// Execution
	{"command", Mapping{"T1059", "Command and Scripting Interpreter", "execution"}},
	{"comando", Mapping{"T1059", "Command and Scripting Interpreter", "execution"}},
	{"script", Mapping{"T1059", "Command and Scripting Interpreter", "execution"}},
	{"powershell", Mapping{"T1059.001", "PowerShell", "execution"}},
	{"shell", Mapping{"T1059", "Command and Scripting Interpreter", "execution"}},

	// Persistence
	{"persistence", Mapping{"T1053", "Scheduled Task/Job", "persistence"}},
	{"persistencia", Mapping{"T1053", "Scheduled Task/Job", "persistence"}},
	{"backdoor", Mapping{"T1547", "Boot or Logon Autostart Execution", "persistence"}},
	{"puerta trasera", Mapping{"T1547", "Boot or Logon Autostart Execution", "persistence"}},

	// Discovery
	{"discovery", Mapping{"T1046", "Network Service Discovery", "discovery"}},
	{"descubrimiento", Mapping{"T1046", "Network Service Discovery", "discovery"}},
	{"enumeration", Mapping{"T1046", "Network Service Discovery", "discovery"}},
	{"enumeración", Mapping{"T1046", "Network Service Discovery", "discovery"}},

	// Generic suspicious
	{"suspicious", Mapping{"T1059", "Command and Scripting Interpreter", "execution"}},
	{"sospechoso", Mapping{"T1059", "Command and Scripting Interpreter", "execution"}},
	{"anomal", Mapping{"T1078", "Valid Accounts", "initial_access"}},
	{"violation", Mapping{"T1078", "Valid Accounts", "initial_access"}},
	{"violación", Mapping{"T1078", "Valid Accounts", "initial_access"}},
	{"policy", Mapping{"T1078", "Valid Accounts", "initial_access"}},
	{"política", Mapping{"T1078", "Valid Accounts", "initial_access"}},
}
