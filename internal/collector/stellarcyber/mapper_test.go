package stellarcyber

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// decodeSource decodes a JSON _source the same way the client does.
func decodeHit(t *testing.T, raw string) Hit {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	var h Hit
	if err := dec.Decode(&h); err != nil {
		t.Fatalf("decoding hit: %v", err)
	}
	return h
}

func roundTrip(t *testing.T, v any) any {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

// TestMapHit_Golden checks the mapper against the fixtures shared with the
// platform's TypeScript mapper.
func TestMapHit_Golden(t *testing.T) {
	searchJSON, err := os.ReadFile("testdata/stellar-alerts-search.json")
	if err != nil {
		t.Fatal(err)
	}
	expectedJSON, err := os.ReadFile("testdata/stellar-alerts-expected-templates.json")
	if err != nil {
		t.Fatal(err)
	}

	var search searchResponse
	dec := json.NewDecoder(bytes.NewReader(searchJSON))
	dec.UseNumber()
	if err := dec.Decode(&search); err != nil {
		t.Fatal(err)
	}
	if search.Hits.Total.Value != 8 || len(search.Hits.Hits) != 8 {
		t.Fatalf("fixture has %d/%d hits, want 8", search.Hits.Total.Value, len(search.Hits.Hits))
	}

	var expected []map[string]any
	if err := json.Unmarshal(expectedJSON, &expected); err != nil {
		t.Fatal(err)
	}

	var got []any
	for _, hit := range search.Hits.Hits {
		template, _, err := MapHit(hit, nil)
		if err != nil {
			t.Fatalf("MapHit(%s): %v", hit.ID, err)
		}
		got = append(got, template)
	}

	var gotMaps []map[string]any
	data, _ := json.Marshal(got)
	if err := json.Unmarshal(data, &gotMaps); err != nil {
		t.Fatal(err)
	}
	if len(gotMaps) != len(expected) {
		t.Fatalf("got %d templates, want %d", len(gotMaps), len(expected))
	}
	for i := range expected {
		if !reflect.DeepEqual(gotMaps[i], expected[i]) {
			gotJSON, _ := json.MarshalIndent(gotMaps[i], "", "  ")
			wantJSON, _ := json.MarshalIndent(expected[i], "", "  ")
			t.Errorf("template %d (%v) differs\n got: %s\nwant: %s", i, expected[i]["externalId"], gotJSON, wantJSON)
		}
	}
	if !reflect.DeepEqual(gotMaps, expected) {
		t.Error("golden templates differ")
	}
}

func TestMapHit_EventTimeFallbackOrder(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   string
	}{
		{"timestamp number", `{"timestamp": 1793318399999, "write_time": 1}`, "2026-10-29"},
		{"timestamp ISO", `{"timestamp": "2026-10-25T23:59:59.999Z"}`, "2026-10-25"},
		{"timestamp ISO with offset", `{"timestamp": "2026-10-25T22:00:00-05:00"}`, "2026-10-26"},
		{"timestamp ISO without zone is UTC", `{"timestamp": "2026-10-25T23:30:00"}`, "2026-10-25"},
		{"timestamp date only", `{"timestamp": "2026-10-25"}`, "2026-10-25"},
		{"timestamp digit string", `{"timestamp": "1793318399999"}`, "2026-10-29"},
		{"alert_time", `{"alert_time": 1793232000000, "write_time": 1}`, "2026-10-29"},
		{"stellar.alert_time", `{"stellar": {"alert_time": 1793145600000}, "write_time": 1}`, "2026-10-28"},
		{"write_time last", `{"write_time": 1793059200000}`, "2026-10-27"},
		{"unparseable timestamp falls through", `{"timestamp": "yesterday", "write_time": 1793059200000}`, "2026-10-27"},
		{"negative timestamp falls through", `{"timestamp": -5, "write_time": 1793059200000}`, "2026-10-27"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hit := decodeHit(t, `{"_index":"i","_id":"x","_source":`+tt.source+`}`)
			template, _, err := MapHit(hit, nil)
			if err != nil {
				t.Fatal(err)
			}
			if template.AlertDate != tt.want {
				t.Errorf("AlertDate = %q, want %q", template.AlertDate, tt.want)
			}
		})
	}
}

func TestMapHit_NoTimeIsAnError(t *testing.T) {
	for _, src := range []string{`{}`, `{"timestamp": "garbage", "write_time": null}`, `{"timestamp": true}`} {
		hit := decodeHit(t, `{"_id":"x","_source":`+src+`}`)
		if _, _, err := MapHit(hit, nil); err == nil {
			t.Errorf("source %s: expected an error", src)
		}
	}
	if _, _, err := MapHit(Hit{ID: "nil-source"}, nil); err == nil {
		t.Error("nil _source: expected an error")
	}
}

func TestMapHit_ReturnsEventTime(t *testing.T) {
	hit := decodeHit(t, `{"_id":"x","_source":{"timestamp":1793196300000}}`)
	_, eventTime, err := MapHit(hit, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := time.UnixMilli(1793196300000).UTC(); !eventTime.Equal(want) || eventTime.Location() != time.UTC {
		t.Errorf("event time = %v, want %v (UTC)", eventTime, want)
	}
}

func TestSeverityFromScore_Bands(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{100, "critical"}, {80, "critical"}, {79.99, "high"}, {60, "high"}, {59.999, "medium"},
		{40, "medium"}, {39.99, "low"}, {20, "low"}, {19.99, "info"}, {0, "info"}, {-1, "info"},
	}
	for _, tt := range tests {
		if got := SeverityFromScore(tt.score); got != tt.want {
			t.Errorf("SeverityFromScore(%v) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

func TestMapHit_ScoreSourceOrder(t *testing.T) {
	tests := []struct {
		source string
		want   string
	}{
		{`{"event_score": 85, "severity": 10, "score": 10}`, "critical"},
		{`{"event_score": "85", "severity": 65, "score": 10}`, "high"}, // strings are not numeric
		{`{"severity": 45, "score": 90}`, "medium"},
		{`{"score": 25}`, "low"},
		{`{}`, "info"},
	}
	for _, tt := range tests {
		hit := decodeHit(t, `{"_id":"x","_source":`+strings.TrimSuffix(tt.source, "}")+sep(tt.source)+`"write_time": 1793059200000}}`)
		template, _, err := MapHit(hit, nil)
		if err != nil {
			t.Fatal(err)
		}
		if template.Severity != tt.want {
			t.Errorf("source %s: Severity = %q, want %q", tt.source, template.Severity, tt.want)
		}
	}
}

func sep(obj string) string {
	if strings.TrimSpace(obj) == "{}" {
		return ""
	}
	return ", "
}

func TestMapHit_TechniqueRules(t *testing.T) {
	tests := []struct {
		name          string
		xdr           string
		wantID        string
		wantName      string
		wantTactic    string
		wantRawTactic any
		wantRawTech   any
	}{
		{
			name:   "MITRE id uppercased",
			xdr:    `{"tactic":{"id":"TA0006","name":"Credential Access"},"technique":{"id":"t1110.001","name":"Password Guessing"}}`,
			wantID: "T1110.001", wantName: "Password Guessing", wantTactic: "TA0006",
			wantRawTactic: map[string]any{"id": "TA0006", "name": "Credential Access"},
			wantRawTech:   map[string]any{"id": "t1110.001", "name": "Password Guessing"},
		},
		{
			name: "XT id falls back to a MITRE ttp, which replaces technique and tactic",
			xdr: `{"tactic":{"id":"XTA0006","name":"XDR Malware"},"technique":{"id":"XT3001","name":"Malware Detected"},
			       "ttps":[{"tactic":{"id":"XTA0006"},"technique":{"id":"XT3001"}},{"tactic":{"id":"TA0002","name":"Execution"},"technique":{"id":"t1059","name":"Command and Scripting Interpreter"}}]}`,
			wantID: "T1059", wantName: "Command and Scripting Interpreter", wantTactic: "TA0002",
			wantRawTactic: map[string]any{"id": "TA0002", "name": "Execution"},
			wantRawTech:   map[string]any{"id": "t1059", "name": "Command and Scripting Interpreter"},
		},
		{
			name:   "XT id kept as-is without a MITRE ttp",
			xdr:    `{"tactic":{"id":"XTA0006","name":"XDR Malware"},"technique":{"id":"XT3001","name":"Malware Detected"}}`,
			wantID: "XT3001", wantName: "Malware Detected", wantTactic: "XTA0006",
			wantRawTactic: map[string]any{"id": "XTA0006", "name": "XDR Malware"},
			wantRawTech:   map[string]any{"id": "XT3001", "name": "Malware Detected"},
		},
		{
			name:   "ttps[0] when technique and tactic are absent",
			xdr:    `{"ttps":[{"tactic":{"id":"TA0010","name":"Exfiltration"},"technique":{"id":"T1041","name":"Exfiltration Over C2 Channel"}}]}`,
			wantID: "T1041", wantName: "Exfiltration Over C2 Channel", wantTactic: "TA0010",
			wantRawTactic: map[string]any{"id": "TA0010", "name": "Exfiltration"},
			wantRawTech:   map[string]any{"id": "T1041", "name": "Exfiltration Over C2 Channel"},
		},
		{
			name:   "names only: T0000, tactic name",
			xdr:    `{"tactic":{"name":"Command and Control"},"technique":{"name":"Protocol Tunneling"}}`,
			wantID: "T0000", wantName: "Protocol Tunneling", wantTactic: "Command and Control",
			wantRawTactic: map[string]any{"name": "Command and Control"},
			wantRawTech:   map[string]any{"name": "Protocol Tunneling"},
		},
		{
			name:   "malformed ids are not MITRE",
			xdr:    `{"technique":{"id":"T110","name":""},"tactic":{"id":"","name":""}}`,
			wantID: "T110", wantName: "", wantTactic: "",
			wantRawTactic: map[string]any{"id": "", "name": ""},
			wantRawTech:   map[string]any{"id": "T110", "name": ""},
		},
		{
			name:   "non-object technique and empty ttps",
			xdr:    `{"technique":"T1566","tactic":null,"ttps":[]}`,
			wantID: "T0000",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hit := decodeHit(t, `{"_id":"x","_source":{"write_time":1793059200000,"xdr_event":`+tt.xdr+`}}`)
			template, _, err := MapHit(hit, nil)
			if err != nil {
				t.Fatal(err)
			}
			if template.TechniqueID != tt.wantID || template.TechniqueName != tt.wantName || template.Tactic != tt.wantTactic {
				t.Errorf("got id=%q name=%q tactic=%q, want %q %q %q", template.TechniqueID, template.TechniqueName, template.Tactic, tt.wantID, tt.wantName, tt.wantTactic)
			}
			raw := roundTrip(t, template.RawData).(map[string]any)
			if !reflect.DeepEqual(raw["tactic"], tt.wantRawTactic) {
				t.Errorf("rawData.tactic = %#v, want %#v", raw["tactic"], tt.wantRawTactic)
			}
			if !reflect.DeepEqual(raw["technique"], tt.wantRawTech) {
				t.Errorf("rawData.technique = %#v, want %#v", raw["technique"], tt.wantRawTech)
			}
		})
	}
}

func TestMapHit_DescriptionAndAsset(t *testing.T) {
	long := strings.Repeat("é", 1200)
	tests := []struct {
		source    string
		wantDesc  string
		wantAsset string
	}{
		{`{"event_name":"Ev","xdr_event":{"display_name":"  ","name":"machine_name"},"host":"h1","srcip_host":"s1"}`, "machine_name", "h1"},
		{`{"event_name":"Ev","dstip_host":"d1","srcip_host":"s1"}`, "Ev", "d1"},
		{`{"hostname":"hn","host":"h1"}`, "Stellar Cyber alert", "hn"},
		{`{"xdr_event":{"display_name":"` + long + `"}}`, strings.Repeat("é", 1000), ""},
	}
	for _, tt := range tests {
		hit := decodeHit(t, `{"_id":"x","_source":`+strings.TrimSuffix(tt.source, "}")+`,"write_time":1793059200000}}`)
		template, _, err := MapHit(hit, nil)
		if err != nil {
			t.Fatal(err)
		}
		if template.Description != tt.wantDesc {
			t.Errorf("Description = %q (len %d), want %q", truncateRunes(template.Description, 40), len([]rune(template.Description)), truncateRunes(tt.wantDesc, 40))
		}
		if template.AssetName != tt.wantAsset {
			t.Errorf("AssetName = %q, want %q", template.AssetName, tt.wantAsset)
		}
	}
}

func TestMapHit_RawDataOnlyPresentKeysAndExtra(t *testing.T) {
	hit := decodeHit(t, `{"_index":"idx","_id":"d1","_source":{"write_time":1793059200000,"tenantid":"t1","event_score":0,"fidelity":null,"xdr_event":{"name":"n","xdr_killchain_stage":"Exploration"}}}`)
	template, _, err := MapHit(hit, map[string]any{"caseId": "c1", "caseName": "Case 1"})
	if err != nil {
		t.Fatal(err)
	}
	got := roundTrip(t, template.RawData)
	want := map[string]any{
		"source": "stellar_cyber", "index": "idx", "tenantId": "t1", "eventScore": float64(0),
		"writeTime": float64(1793059200000), "eventName": "n", "killchainStage": "Exploration",
		"caseId": "c1", "caseName": "Case 1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rawData = %#v\nwant %#v", got, want)
	}
	if template.ExternalID != "d1" || template.SourceIP != "" || template.DestinationIP != "" || template.ImpactType != "" {
		t.Errorf("unexpected template %+v", template)
	}
}

func TestMapHit_NumbersAreExact(t *testing.T) {
	hit := decodeHit(t, `{"_id":"x","_source":{"write_time":1793059200001,"event_score":79.99000000000001}}`)
	template, _, err := MapHit(hit, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(template.RawData)
	if !strings.Contains(string(data), `"writeTime":1793059200001`) || !strings.Contains(string(data), `"eventScore":79.99000000000001`) {
		t.Errorf("numbers not preserved: %s", data)
	}
}

func TestTruncateRunes(t *testing.T) {
	if got := truncateRunes("añb", 2); got != "añ" {
		t.Errorf("got %q", got)
	}
	if got := truncateRunes("ab", 5); got != "ab" {
		t.Errorf("got %q", got)
	}
	if got := truncateRunes("", 0); got != "" {
		t.Errorf("got %q", got)
	}
}
