package qradar

import (
	"regexp"
	"strings"
)

// MITRE technique patterns extracted from QRadar offense descriptions and categories.
// This mirrors the extractMitreFromDescription logic from the platform's qradar-adapter.ts.
var mitreTechniqueRegex = regexp.MustCompile(`T\d{4}(?:\.\d{3})?`)

// categoryToMITRE maps common QRadar offense categories to MITRE ATT&CK techniques.
var categoryToMITRE = map[string]struct {
	TechniqueID   string
	TechniqueName string
	ImpactType    string
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
	"Policy Violation":  {"T1078", "Valid Accounts", "initial_access"},
	"Access Violation":  {"T1078", "Valid Accounts", "initial_access"},
	"Anomaly":           {"T1078", "Valid Accounts", "initial_access"},
	"Audit":             {"T1078", "Valid Accounts", "defense_evasion"},
	"Compliance":        {"T1078", "Valid Accounts", "initial_access"},

	// Software & System
	"Software Change":    {"T1562", "Impair Defenses", "defense_evasion"},
	"Application":        {"T1059", "Command and Scripting Interpreter", "execution"},
	"System":             {"T1059", "Command and Scripting Interpreter", "execution"},
	"Configuration":      {"T1562", "Impair Defenses", "defense_evasion"},
	"Firewall":           {"T1562.004", "Disable or Modify System Firewall", "defense_evasion"},

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

// MITREMapping holds the extracted MITRE technique info.
type MITREMapping struct {
	TechniqueID   string
	TechniqueName string
	ImpactType    string
}

// ExtractMITRE attempts to extract MITRE ATT&CK technique from offense description and categories.
// Priority: 1) T-code in description text, 2) exact category match, 3) partial category match,
// 4) keyword in description, 5) default fallback (never returns empty).
func ExtractMITRE(description string, categories []string) MITREMapping {
	// Try to find T-code directly in the description (e.g., "T1110", "T1059.001")
	if matches := mitreTechniqueRegex.FindStringSubmatch(description); len(matches) > 0 {
		return MITREMapping{
			TechniqueID: matches[0],
			ImpactType:  "unknown",
		}
	}

	// Try exact category-based mapping
	for _, cat := range categories {
		cat = strings.TrimSpace(cat)
		if mapping, ok := categoryToMITRE[cat]; ok {
			return MITREMapping{
				TechniqueID:   mapping.TechniqueID,
				TechniqueName: mapping.TechniqueName,
				ImpactType:    mapping.ImpactType,
			}
		}
	}

	// Try partial matching on categories
	for _, cat := range categories {
		catLower := strings.ToLower(cat)
		for keyword, mapping := range categoryToMITRE {
			if strings.Contains(catLower, strings.ToLower(keyword)) {
				return MITREMapping{
					TechniqueID:   mapping.TechniqueID,
					TechniqueName: mapping.TechniqueName,
					ImpactType:    mapping.ImpactType,
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
	return MITREMapping{
		TechniqueID:   "T1059",
		TechniqueName: "Command and Scripting Interpreter",
		ImpactType:    "execution",
	}
}

// descriptionKeyword pairs a keyword with its MITRE mapping.
type descriptionKeyword struct {
	keyword string
	mapping MITREMapping
}

// descriptionKeywords maps keywords found in offense descriptions to MITRE techniques.
// Includes both English and Spanish terms common in QRadar deployments.
var descriptionKeywords = []descriptionKeyword{
	// Authentication / Credentials
	{"brute force", MITREMapping{"T1110", "Brute Force", "credential_access"}},
	{"fuerza bruta", MITREMapping{"T1110", "Brute Force", "credential_access"}},
	{"failed login", MITREMapping{"T1110", "Brute Force", "credential_access"}},
	{"login failure", MITREMapping{"T1110", "Brute Force", "credential_access"}},
	{"inicio de sesión fallido", MITREMapping{"T1110", "Brute Force", "credential_access"}},
	{"autenticación fallida", MITREMapping{"T1110", "Brute Force", "credential_access"}},
	{"credential", MITREMapping{"T1003", "OS Credential Dumping", "credential_access"}},
	{"credencial", MITREMapping{"T1003", "OS Credential Dumping", "credential_access"}},
	{"password spray", MITREMapping{"T1110.003", "Password Spraying", "credential_access"}},

	// Malware
	{"malware", MITREMapping{"T1204", "User Execution", "execution"}},
	{"ransomware", MITREMapping{"T1486", "Data Encrypted for Impact", "impact"}},
	{"phishing", MITREMapping{"T1566", "Phishing", "initial_access"}},
	{"trojan", MITREMapping{"T1204", "User Execution", "execution"}},
	{"troyano", MITREMapping{"T1204", "User Execution", "execution"}},
	{"virus", MITREMapping{"T1204", "User Execution", "execution"}},

	// Network / Scanning
	{"scan", MITREMapping{"T1595", "Active Scanning", "reconnaissance"}},
	{"escaneo", MITREMapping{"T1595", "Active Scanning", "reconnaissance"}},
	{"denial of service", MITREMapping{"T1498", "Network Denial of Service", "impact"}},
	{"denegación de servicio", MITREMapping{"T1498", "Network Denial of Service", "impact"}},
	{"ddos", MITREMapping{"T1498", "Network Denial of Service", "impact"}},

	// Data
	{"exfiltration", MITREMapping{"T1041", "Exfiltration Over C2 Channel", "exfiltration"}},
	{"exfiltración", MITREMapping{"T1041", "Exfiltration Over C2 Channel", "exfiltration"}},
	{"data loss", MITREMapping{"T1567", "Exfiltration Over Web Service", "exfiltration"}},
	{"pérdida de datos", MITREMapping{"T1567", "Exfiltration Over Web Service", "exfiltration"}},
	{"destrucción", MITREMapping{"T1485", "Data Destruction", "impact"}},
	{"destruction", MITREMapping{"T1485", "Data Destruction", "impact"}},

	// Privilege / Access
	{"privilege", MITREMapping{"T1068", "Exploitation for Privilege Escalation", "privilege_escalation"}},
	{"privilegio", MITREMapping{"T1068", "Exploitation for Privilege Escalation", "privilege_escalation"}},
	{"escalation", MITREMapping{"T1068", "Exploitation for Privilege Escalation", "privilege_escalation"}},
	{"escalamiento", MITREMapping{"T1068", "Exploitation for Privilege Escalation", "privilege_escalation"}},
	{"lateral", MITREMapping{"T1021", "Remote Services", "lateral_movement"}},
	{"unauthorized access", MITREMapping{"T1078", "Valid Accounts", "initial_access"}},
	{"acceso no autorizado", MITREMapping{"T1078", "Valid Accounts", "initial_access"}},

	// Software / System changes
	{"uninstall", MITREMapping{"T1562", "Impair Defenses", "defense_evasion"}},
	{"desinstalación", MITREMapping{"T1562", "Impair Defenses", "defense_evasion"}},
	{"desinstalar", MITREMapping{"T1562", "Impair Defenses", "defense_evasion"}},
	{"software no autorizado", MITREMapping{"T1562", "Impair Defenses", "defense_evasion"}},
	{"unauthorized software", MITREMapping{"T1562", "Impair Defenses", "defense_evasion"}},
	{"instalación no autorizada", MITREMapping{"T1072", "Software Deployment Tools", "execution"}},
	{"unauthorized install", MITREMapping{"T1072", "Software Deployment Tools", "execution"}},
	{"disabled", MITREMapping{"T1562", "Impair Defenses", "defense_evasion"}},
	{"deshabilitado", MITREMapping{"T1562", "Impair Defenses", "defense_evasion"}},
	{"firewall", MITREMapping{"T1562.004", "Disable or Modify System Firewall", "defense_evasion"}},
	{"antivirus", MITREMapping{"T1562.001", "Disable or Modify Tools", "defense_evasion"}},

	// Execution
	{"command", MITREMapping{"T1059", "Command and Scripting Interpreter", "execution"}},
	{"comando", MITREMapping{"T1059", "Command and Scripting Interpreter", "execution"}},
	{"script", MITREMapping{"T1059", "Command and Scripting Interpreter", "execution"}},
	{"powershell", MITREMapping{"T1059.001", "PowerShell", "execution"}},
	{"shell", MITREMapping{"T1059", "Command and Scripting Interpreter", "execution"}},

	// Persistence
	{"persistence", MITREMapping{"T1053", "Scheduled Task/Job", "persistence"}},
	{"persistencia", MITREMapping{"T1053", "Scheduled Task/Job", "persistence"}},
	{"backdoor", MITREMapping{"T1547", "Boot or Logon Autostart Execution", "persistence"}},
	{"puerta trasera", MITREMapping{"T1547", "Boot or Logon Autostart Execution", "persistence"}},

	// Discovery
	{"discovery", MITREMapping{"T1046", "Network Service Discovery", "discovery"}},
	{"descubrimiento", MITREMapping{"T1046", "Network Service Discovery", "discovery"}},
	{"enumeration", MITREMapping{"T1046", "Network Service Discovery", "discovery"}},
	{"enumeración", MITREMapping{"T1046", "Network Service Discovery", "discovery"}},

	// Generic suspicious
	{"suspicious", MITREMapping{"T1059", "Command and Scripting Interpreter", "execution"}},
	{"sospechoso", MITREMapping{"T1059", "Command and Scripting Interpreter", "execution"}},
	{"anomal", MITREMapping{"T1078", "Valid Accounts", "initial_access"}},
	{"violation", MITREMapping{"T1078", "Valid Accounts", "initial_access"}},
	{"violación", MITREMapping{"T1078", "Valid Accounts", "initial_access"}},
	{"policy", MITREMapping{"T1078", "Valid Accounts", "initial_access"}},
	{"política", MITREMapping{"T1078", "Valid Accounts", "initial_access"}},
}
