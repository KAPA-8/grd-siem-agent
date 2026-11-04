// Package mitre holds SIEM-agnostic heuristics that infer a MITRE ATT&CK
// technique from free text (alert descriptions) and SIEM categories. It is
// used for sources that do not carry native ATT&CK data (e.g. QRadar offenses).
package mitre

import (
	"regexp"
	"sort"
	"strings"
)

// MITRE technique patterns extracted from alert descriptions and categories.
// This mirrors the extractMitreFromDescription logic from the platform's qradar-adapter.ts.
var mitreTechniqueRegex = regexp.MustCompile(`T\d{4}(?:\.\d{3})?`)

// categoryRule maps a SIEM category (or a keyword inside one) to a technique.
type categoryRule struct {
	category string
	mapping  Mapping
}

// categoryRules maps common SIEM (QRadar) categories to MITRE ATT&CK
// techniques; Mapping.Tactic is the ATT&CK tactic in snake_case. It is a slice,
// not a map, so that partial matching is deterministic (see partialCategoryRules).
var categoryRules = []categoryRule{
	// Authentication & Credentials
	{"Authentication", Mapping{"T1110", "Brute Force", "credential_access"}},
	{"User Login Failure", Mapping{"T1110", "Brute Force", "credential_access"}},
	{"User Login Success", Mapping{"T1078", "Valid Accounts", "credential_access"}},
	{"Suspicious Activity", Mapping{"T1059", "Command and Scripting Interpreter", "execution"}},
	{"Authentication Failure", Mapping{"T1110", "Brute Force", "credential_access"}},
	{"Credential Theft", Mapping{"T1003", "OS Credential Dumping", "credential_access"}},

	// Malware & Exploits
	{"Malware", Mapping{"T1204", "User Execution", "execution"}},
	{"Exploit", Mapping{"T1203", "Exploitation for Client Execution", "execution"}},
	{"Virus/Worm", Mapping{"T1204", "User Execution", "execution"}},
	{"Trojan", Mapping{"T1204", "User Execution", "execution"}},
	{"Ransomware", Mapping{"T1486", "Data Encrypted for Impact", "impact"}},
	{"Botnet", Mapping{"T1583", "Acquire Infrastructure", "resource_development"}},
	{"Spyware", Mapping{"T1005", "Data from Local System", "collection"}},

	// Network
	{"Denial of Service", Mapping{"T1498", "Network Denial of Service", "impact"}},
	{"DoS", Mapping{"T1498", "Network Denial of Service", "impact"}},
	{"Reconnaissance", Mapping{"T1595", "Active Scanning", "reconnaissance"}},
	{"Scan", Mapping{"T1595", "Active Scanning", "reconnaissance"}},
	{"Port Scan", Mapping{"T1046", "Network Service Discovery", "discovery"}},
	{"Network Anomaly", Mapping{"T1071", "Application Layer Protocol", "command_and_control"}},

	// Policy & Access
	{"Policy Violation", Mapping{"T1078", "Valid Accounts", "initial_access"}},
	{"Access Violation", Mapping{"T1078", "Valid Accounts", "initial_access"}},
	{"Anomaly", Mapping{"T1078", "Valid Accounts", "initial_access"}},
	{"Audit", Mapping{"T1078", "Valid Accounts", "defense_evasion"}},
	{"Compliance", Mapping{"T1078", "Valid Accounts", "initial_access"}},

	// Software & System
	{"Software Change", Mapping{"T1562", "Impair Defenses", "defense_evasion"}},
	{"Application", Mapping{"T1059", "Command and Scripting Interpreter", "execution"}},
	{"System", Mapping{"T1059", "Command and Scripting Interpreter", "execution"}},
	{"Configuration", Mapping{"T1562", "Impair Defenses", "defense_evasion"}},
	{"Firewall", Mapping{"T1562.004", "Disable or Modify System Firewall", "defense_evasion"}},

	// Data
	{"Data Exfiltration", Mapping{"T1041", "Exfiltration Over C2 Channel", "exfiltration"}},
	{"Data Loss", Mapping{"T1567", "Exfiltration Over Web Service", "exfiltration"}},
	{"Data Destruction", Mapping{"T1485", "Data Destruction", "impact"}},

	// Command & Control
	{"Command and Control", Mapping{"T1071", "Application Layer Protocol", "command_and_control"}},
	{"C2", Mapping{"T1071", "Application Layer Protocol", "command_and_control"}},
	{"CnC", Mapping{"T1071", "Application Layer Protocol", "command_and_control"}},

	// Lateral Movement
	{"Lateral Movement", Mapping{"T1021", "Remote Services", "lateral_movement"}},

	// Privilege Escalation
	{"Privilege Escalation", Mapping{"T1068", "Exploitation for Privilege Escalation", "privilege_escalation"}},
}

// exactCategoryRules indexes categoryRules for exact (case-sensitive) lookups.
var exactCategoryRules = func() map[string]Mapping {
	m := make(map[string]Mapping, len(categoryRules))
	for _, r := range categoryRules {
		m[r.category] = r.mapping
	}
	return m
}()

// partialCategoryRules is categoryRules ordered for substring matching: the
// longest (most specific) keyword first, ties in declaration order. For
// example "Port Scan Detected" matches "Port Scan" (T1046) before "Scan".
var partialCategoryRules = func() []categoryRule {
	rules := make([]categoryRule, len(categoryRules))
	copy(rules, categoryRules)
	sort.SliceStable(rules, func(i, j int) bool {
		return len(rules[i].category) > len(rules[j].category)
	})
	for i := range rules {
		rules[i].category = strings.ToLower(rules[i].category)
	}
	return rules
}()

// Mapping holds the inferred MITRE technique info. Tactic is the ATT&CK tactic
// in snake_case (e.g. "credential_access"); the platform derives the FAIR
// impact type from it when the technique is not in its catalog.
type Mapping struct {
	TechniqueID   string
	TechniqueName string
	Tactic        string
}

// Extract attempts to infer a MITRE ATT&CK technique from a description and categories.
// Priority: 1) T-code in description text, 2) exact category match, 3) partial category
// match (longest keyword first), 4) keyword in description, 5) default fallback (never
// returns empty). The result is deterministic for a given input.
func Extract(description string, categories []string) Mapping {
	// Try to find T-code directly in the description (e.g., "T1110", "T1059.001")
	if matches := mitreTechniqueRegex.FindStringSubmatch(description); len(matches) > 0 {
		return Mapping{TechniqueID: matches[0]}
	}

	// Try exact category-based mapping (categories in their given order)
	for _, cat := range categories {
		if mapping, ok := exactCategoryRules[strings.TrimSpace(cat)]; ok {
			return mapping
		}
	}

	// Try partial matching on categories. Iterating an ordered slice (not a
	// map) keeps the result identical from one run to the next.
	for _, cat := range categories {
		catLower := strings.ToLower(cat)
		for _, rule := range partialCategoryRules {
			if strings.Contains(catLower, rule.category) {
				return rule.mapping
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
