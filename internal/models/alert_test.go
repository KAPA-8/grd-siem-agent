package models

import (
	"encoding/json"
	"strings"
	"testing"
)

// The source-state fields follow the platform contract: absent unless set,
// and an explicit fairExcluded:false is sent (it clears the stored flag of a
// reopened alert), while statusOnly appears only when true.
func TestAlertImportTemplate_SourceStateJSON(t *testing.T) {
	plain, _ := json.Marshal(AlertImportTemplate{TechniqueID: "T0000"})
	for _, key := range []string{"sourceStatus", "fairExcluded", "signalClass", "statusOnly"} {
		if strings.Contains(string(plain), key) {
			t.Errorf("%s present in %s", key, plain)
		}
	}
	withState, _ := json.Marshal(AlertImportTemplate{SourceStatus: "active", FairExcluded: Bool(false), SignalClass: SignalClassThreatEvent})
	for _, want := range []string{`"sourceStatus":"active"`, `"fairExcluded":false`, `"signalClass":"threat_event"`} {
		if !strings.Contains(string(withState), want) {
			t.Errorf("%s lacks %s", withState, want)
		}
	}
	if strings.Contains(string(withState), "statusOnly") {
		t.Errorf("statusOnly false must be omitted: %s", withState)
	}
	statusOnly, _ := json.Marshal(AlertImportTemplate{StatusOnly: true})
	if !strings.Contains(string(statusOnly), `"statusOnly":true`) {
		t.Errorf("%s", statusOnly)
	}
}

func TestNormalizeSourceStatus(t *testing.T) {
	if got := NormalizeSourceStatus("  In Progress "); got != "in progress" {
		t.Errorf("got %q", got)
	}
	long := strings.Repeat("á", 70)
	if got := NormalizeSourceStatus(long); len([]rune(got)) != MaxSourceStatusLength {
		t.Errorf("length = %d runes", len([]rune(got)))
	}
}

func TestSyncResponse_OptionalCounters(t *testing.T) {
	var old SyncResponse
	if err := json.Unmarshal([]byte(`{"success":true,"alerts_imported":1}`), &old); err != nil || old.AlertsExcluded != 0 || old.AlertsStatusUpdated != 0 {
		t.Errorf("older platform: %+v %v", old, err)
	}
}
