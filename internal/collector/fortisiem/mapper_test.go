package fortisiem

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// parityCase is one case of testdata/fortisiem-incidents-parity-cases.json,
// the fixture shared with the platform's TypeScript mapper.
type parityCase struct {
	Name     string          `json:"name"`
	Incident json.RawMessage `json:"incident"`
	Window   *struct {
		From string `json:"from"`
		To   string `json:"to"`
	} `json:"window"`
	Options *struct {
		SecurityOnly *bool  `json:"securityOnly"`
		TenantID     string `json:"tenantId"`
		MinSeverity  string `json:"minSeverity"`
	} `json:"options"`
	Expected json.RawMessage `json:"expected"`
}

func loadParityCases(t *testing.T) []parityCase {
	t.Helper()
	data, err := os.ReadFile("testdata/fortisiem-incidents-parity-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []parityCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	return cases
}

// decodeIncident decodes an incident the same way the client does.
func decodeIncident(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var inc map[string]any
	if err := dec.Decode(&inc); err != nil {
		t.Fatalf("decoding incident: %v", err)
	}
	return inc
}

// normalizeJSON decodes JSON (numbers as json.Number) for a deep comparison.
func normalizeJSON(t *testing.T, raw []byte) any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("decoding %s: %v", raw, err)
	}
	return v
}

func (c parityCase) options(t *testing.T) MapOptions {
	t.Helper()
	var opts MapOptions
	if c.Options != nil {
		opts.SecurityOnly = c.Options.SecurityOnly != nil && *c.Options.SecurityOnly
		opts.TenantID = c.Options.TenantID
		severity, err := minSeverityFor(c.Options.MinSeverity)
		if err != nil {
			t.Fatal(err)
		}
		opts.MinSeverity = severity
	}
	if c.Window != nil {
		from, err1 := time.Parse(time.RFC3339Nano, c.Window.From)
		to, err2 := time.Parse(time.RFC3339Nano, c.Window.To)
		if err1 != nil || err2 != nil {
			t.Fatalf("window: %v %v", err1, err2)
		}
		opts.Window = &Window{From: from.UnixMilli(), To: to.UnixMilli()}
	}
	return opts
}

// TestMapIncident_PlatformParity checks every case of the shared fixture:
// the template must equal "expected" field by field (rawData keeps the JSON
// types), or the incident must be dropped when "expected" is null.
func TestMapIncident_PlatformParity(t *testing.T) {
	cases := loadParityCases(t)
	if len(cases) < 100 {
		t.Fatalf("parity fixture has %d cases, want the full fixture (>= 100)", len(cases))
	}
	names := map[string]bool{}
	dropped, statusOnly := 0, 0
	for _, c := range cases {
		if names[c.Name] {
			t.Fatalf("duplicate case name %q", c.Name)
		}
		names[c.Name] = true
		t.Run(c.Name, func(t *testing.T) {
			template, err := MapIncident(decodeIncident(t, c.Incident), c.options(t))
			if string(bytes.TrimSpace(c.Expected)) == "null" {
				dropped++
				if err == nil {
					t.Fatalf("expected the incident to be dropped, got %+v", template)
				}
				return
			}
			if err != nil {
				t.Fatalf("MapIncident: %v", err)
			}
			if template.StatusOnly {
				statusOnly++
			}
			data, err := json.Marshal(template)
			if err != nil {
				t.Fatal(err)
			}
			got, want := normalizeJSON(t, data), normalizeJSON(t, c.Expected)
			if !reflect.DeepEqual(got, want) {
				gotJSON, _ := json.MarshalIndent(got, "", "  ")
				wantJSON, _ := json.MarshalIndent(want, "", "  ")
				t.Errorf("template differs\n got: %s\nwant: %s", gotJSON, wantJSON)
			}
		})
	}
	if dropped < 10 || statusOnly < 5 {
		t.Errorf("fixture covers %d dropped and %d statusOnly cases; expected the full fixture", dropped, statusOnly)
	}
}

func TestMapIncident_DropReasons(t *testing.T) {
	tests := []struct {
		name     string
		incident string
		opts     MapOptions
		want     error
	}{
		{"no id", `{"incidentFirstSeen": 1795168800000}`, MapOptions{}, errNoID},
		{"fractional id", `{"incidentId": 1.5, "incidentFirstSeen": 1795168800000}`, MapOptions{}, errNoID},
		{"blank id", `{"incidentId": "  ", "incidentFirstSeen": 1795168800000}`, MapOptions{}, errNoID},
		{"no first seen", `{"incidentId": 1}`, MapOptions{}, errNoFirstSeen},
		{"negative first seen", `{"incidentId": 1, "incidentFirstSeen": -1}`, MapOptions{}, errNoFirstSeen},
		{"first seen after year 9999", `{"incidentId": 1, "incidentFirstSeen": 253402300800000}`, MapOptions{}, errNoFirstSeen},
		{"not security", `{"incidentId": 1, "incidentFirstSeen": 1795168800000, "phIncidentCategory": "Change"}`, MapOptions{SecurityOnly: true}, errFiltered},
		{"other tenant", `{"incidentId": 1, "incidentFirstSeen": 1795168800000, "customer": "Org A", "phCustId": 2001}`, MapOptions{TenantID: "orgb"}, errFiltered},
		{"below min severity", `{"incidentId": 1, "incidentFirstSeen": 1795168800000, "eventSeverity": 3}`, MapOptions{MinSeverity: "medium"}, errFiltered},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := MapIncident(decodeIncident(t, []byte(tt.incident)), tt.opts)
			if !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestMapIncident_TenantMatchesCustomerOrIDs(t *testing.T) {
	inc := `{"incidentId": 1, "incidentFirstSeen": 1795168800000, "customer": "Org Synth A", "phCustId": 2001, "custId": "2001"}`
	for _, tenant := range []string{"orgsyntha", " ORG SYNTH A ", "2001"} {
		if _, err := MapIncident(decodeIncident(t, []byte(inc)), MapOptions{TenantID: tenant}); err != nil {
			t.Errorf("tenant %q: %v", tenant, err)
		}
	}
	only := `{"incidentId": 1, "incidentFirstSeen": 1795168800000, "custId": 3005}`
	if _, err := MapIncident(decodeIncident(t, []byte(only)), MapOptions{TenantID: "3005"}); err != nil {
		t.Errorf("custId alone: %v", err)
	}
}

func TestMapIncident_StatusOnlyWindowIsClosed(t *testing.T) {
	inc := decodeIncident(t, []byte(`{"incidentId": 7, "incidentFirstSeen": 1000}`))
	for _, tt := range []struct {
		window Window
		want   bool
	}{
		{Window{From: 1000, To: 1000}, false},
		{Window{From: 1001, To: 2000}, true},
		{Window{From: 0, To: 999}, true},
	} {
		got, err := MapIncident(inc, MapOptions{Window: &tt.window})
		if err != nil {
			t.Fatal(err)
		}
		if got.StatusOnly != tt.want {
			t.Errorf("window %+v: statusOnly = %v, want %v", tt.window, got.StatusOnly, tt.want)
		}
	}
	if got, _ := MapIncident(inc, MapOptions{}); got.StatusOnly {
		t.Error("without a window an incident is never statusOnly")
	}
}

// The template always carries fairExcluded (false too) and signalClass, so
// a reopened incident clears the flag stored for it.
func TestMapIncident_AlwaysSendsFairExcluded(t *testing.T) {
	got, err := MapIncident(decodeIncident(t, []byte(`{"incidentId": 9, "incidentFirstSeen": 1795168800000, "incidentStatus": "Active", "incidentReso": "True Positive"}`)), MapOptions{})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(got)
	for _, want := range []string{`"fairExcluded":false`, `"signalClass":"threat_event"`, `"sourceStatus":"active/true_positive"`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("template %s lacks %s", data, want)
		}
	}
	if strings.Contains(string(data), "statusOnly") {
		t.Errorf("statusOnly must be omitted when false: %s", data)
	}
}
