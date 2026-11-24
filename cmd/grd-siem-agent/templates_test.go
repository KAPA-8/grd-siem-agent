package main

import (
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// The config templates shipped in configs/ and scripts/ must stay loadable:
// once the placeholders are filled in, validate accepts them.

var placeholderValues = []struct {
	pattern *regexp.Regexp
	value   string
}{
	{regexp.MustCompile(`(?m)^(\s*)url: ""`), `${1}url: "https://grd.example.com"`},
	{regexp.MustCompile(`(?m)^(\s*)agent_token: ""`), `${1}agent_token: "grd_agent_x"`},
	{regexp.MustCompile(`(?m)^(\s*)connection_id: ""`), `${1}connection_id: "3f6c1d2e-8a4b-4c5d-9e6f-7a8b9c0d1e2f"`},
	{regexp.MustCompile(`(?m)^(\s*)api_url: ""`), `${1}api_url: "https://siem.example.com"`},
	{regexp.MustCompile(`(?m)^(\s*)api_key: ""`), `${1}api_key: "secret"`},
	{regexp.MustCompile(`(?m)^(\s*)username: ""`), `${1}username: "api@acme.com"`},
	{regexp.MustCompile(`(?m)^(\s*)password: ''`), `${1}password: 'p:a$s"w''o@r/d'`},
}

func fillPlaceholders(yaml string) string {
	for _, p := range placeholderValues {
		yaml = p.pattern.ReplaceAllString(yaml, p.value)
	}
	return yaml
}

func validateTemplate(t *testing.T, name, yaml, wantType string) {
	t.Helper()
	out, err := runValidate(t, writeTestConfig(t, fillPlaceholders(yaml)))
	if err != nil {
		t.Fatalf("%s: validate failed: %v\n%s", name, err, yaml)
	}
	if !strings.Contains(out, "SIEM Type:     "+wantType) {
		t.Errorf("%s: output = %s", name, out)
	}
}

func readRepoFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(data), "\r\n", "\n")
}

func TestTemplates_InstallSh(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("install.sh is for Linux")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	for _, siemType := range []string{"qradar", "stellar_cyber", "fortisiem"} {
		out, err := exec.Command(bash, "../../scripts/install.sh", "--siem-type", siemType, "--print-config").Output()
		if err != nil {
			t.Fatalf("install.sh --print-config %s: %v", siemType, err)
		}
		validateTemplate(t, "install.sh "+siemType, string(out), siemType)
	}
	if err := exec.Command(bash, "../../scripts/install.sh", "--siem-type", "splunk", "--print-config").Run(); err == nil {
		t.Error("install.sh accepted an unsupported --siem-type")
	}
}

// install.ps1 cannot run here; its here-strings are expanded the way
// PowerShell would ($siem and the data/log directory expressions).
func TestTemplates_InstallPs1(t *testing.T) {
	script := readRepoFile(t, "../../scripts/install.ps1")
	hereStrings := regexp.MustCompile(`(?s)@"\n(.*?)\n"@`).FindAllStringSubmatch(script, -1)
	if len(hereStrings) != 4 {
		t.Fatalf("found %d here-strings in install.ps1, want 4 (stellar_cyber, fortisiem, qradar, config)", len(hereStrings))
	}
	stellar, fortisiem, qradar, config := hereStrings[0][1], hereStrings[1][1], hereStrings[2][1], hereStrings[3][1]
	if !strings.Contains(stellar, `type: "stellar_cyber"`) || !strings.Contains(fortisiem, `type: "fortisiem"`) || !strings.Contains(qradar, `type: "qradar"`) {
		t.Fatal("unexpected here-string order in install.ps1")
	}
	if !strings.Contains(script, `[ValidateSet("qradar", "stellar_cyber", "fortisiem")]`) {
		t.Error("install.ps1 -SiemType does not accept fortisiem")
	}
	expand := strings.NewReplacer(
		`$($DataDir -replace '\\', '/')`, "C:/ProgramData/GRD SIEM Agent/data",
		`$($LogDir -replace '\\', '/')`, "C:/ProgramData/GRD SIEM Agent/logs",
	)
	for siemType, siem := range map[string]string{"qradar": qradar, "stellar_cyber": stellar, "fortisiem": fortisiem} {
		yaml := expand.Replace(strings.Replace(config, "$siem", siem, 1))
		if strings.Contains(yaml, "$") {
			t.Fatalf("unexpanded PowerShell expression in the %s template:\n%s", siemType, yaml)
		}
		validateTemplate(t, "install.ps1 "+siemType, yaml, siemType)
	}
}

func TestTemplates_ConfigExample(t *testing.T) {
	example := readRepoFile(t, "../../configs/config.example.yaml")
	validateTemplate(t, "config.example.yaml (qradar)", example, "qradar")

	// The Stellar Cyber and FortiSIEM blocks are commented out; swap each in
	// for the QRadar one.
	lines := strings.Split(example, "\n")
	var blocks [][]string
	for i := 0; i < len(lines); i++ {
		if lines[i] != "# siem:" {
			continue
		}
		var block []string
		for ; i < len(lines) && strings.HasPrefix(lines[i], "#"); i++ {
			block = append(block, strings.TrimPrefix(strings.TrimPrefix(lines[i], "#"), " "))
		}
		blocks = append(blocks, block)
	}
	if len(blocks) != 2 || len(blocks[0]) < 10 || len(blocks[1]) < 10 {
		t.Fatalf("found %d commented siem blocks in config.example.yaml, want 2 (stellar_cyber, fortisiem)", len(blocks))
	}
	qradar := regexp.MustCompile(`(?s)\nsiem:\n  type: "qradar".*?\n\n`)
	if !qradar.MatchString(example) {
		t.Fatal("QRadar siem block not found in config.example.yaml")
	}
	for i, siemType := range []string{"stellar_cyber", "fortisiem"} {
		swapped := qradar.ReplaceAllLiteralString(example, "\n"+strings.Join(blocks[i], "\n")+"\n\n")
		validateTemplate(t, "config.example.yaml ("+siemType+")", swapped, siemType)
	}
}
