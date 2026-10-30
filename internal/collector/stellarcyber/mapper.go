package stellarcyber

import (
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/grd-platform/grd-siem-agent/internal/models"
)

// The mapping below is shared with the platform's TypeScript adapter
// (lib/integrations/siem/stellar-cyber/mapper.ts). Both are checked against
// the same golden fixtures (testdata/stellar-alerts-*.json); keep them in sync.

const (
	sourceName          = "stellar_cyber"
	unmappedTechniqueID = "T0000"
	fallbackDescription = "Stellar Cyber alert"
	maxDescriptionRunes = 1000
	alertDateLayout     = "2006-01-02"
)

// mitreTechniqueID matches a MITRE ATT&CK technique or sub-technique ID.
var mitreTechniqueID = regexp.MustCompile(`(?i)^T\d{4}(\.\d{3})?$`)

// Hit is one alert document as returned by the _search API ({_index, _id,
// _source}) and by /cases/{id}/alerts (which may add "found").
type Hit struct {
	Index  string         `json:"_index"`
	ID     string         `json:"_id"`
	Source map[string]any `json:"_source"`
	Found  *bool          `json:"found,omitempty"`
}

var errNoEventTime = errors.New("alert has no usable timestamp (timestamp, alert_time, stellar.alert_time, write_time)")

// MapHit converts an alert hit into the platform's AlertImportTemplate and
// returns the alert's event time. extra is merged into rawData (cases mode
// passes caseId and caseName). It fails only when the alert has no usable
// event time, since the platform cannot import an alert without a date.
func MapHit(hit Hit, extra map[string]any) (models.AlertImportTemplate, time.Time, error) {
	s := hit.Source
	if s == nil {
		s = map[string]any{}
	}
	x := asObject(s["xdr_event"])

	eventTime, ok := eventTimeOf(s)
	if !ok {
		return models.AlertImportTemplate{}, time.Time{}, errNoEventTime
	}

	tech, tac := techniqueAndTactic(x)

	template := models.AlertImportTemplate{
		ExternalID:    hit.ID,
		TechniqueID:   resolveTechniqueID(x, &tech, &tac),
		TechniqueName: str(tech["name"]),
		Description:   truncateRunes(firstNonEmpty(str(x["display_name"]), str(x["name"]), str(s["event_name"]), fallbackDescription), maxDescriptionRunes),
		AlertDate:     eventTime.UTC().Format(alertDateLayout),
		Severity:      SeverityFromScore(alertScore(s)),
		SourceIP:      str(s["srcip"]),
		DestinationIP: str(s["dstip"]),
		AssetName:     firstNonEmpty(str(s["hostname"]), str(s["host"]), str(s["dstip_host"]), str(s["srcip_host"])),
		Tactic:        firstNonEmpty(str(tac["id"]), str(tac["name"])),
		RawData:       rawData(hit, s, x, tech, tac, extra),
	}
	return template, eventTime, nil
}

// techniqueAndTactic returns x.technique / x.tactic when they are objects,
// else the ones of x.ttps[0].
func techniqueAndTactic(x map[string]any) (tech, tac map[string]any) {
	tech = asObject(x["technique"])
	tac = asObject(x["tactic"])
	if tech == nil || tac == nil {
		if ttps := asArray(x["ttps"]); len(ttps) > 0 {
			first := asObject(ttps[0])
			if tech == nil {
				tech = asObject(first["technique"])
			}
			if tac == nil {
				tac = asObject(first["tactic"])
			}
		}
	}
	return tech, tac
}

// resolveTechniqueID applies DESIGN §2: a MITRE-shaped tech.id (uppercased);
// else the first MITRE-shaped x.ttps[i].technique.id, whose technique and
// tactic objects then replace tech and tac; else a non-empty tech.id as-is
// (Stellar's own XT... IDs); else T0000.
func resolveTechniqueID(x map[string]any, tech, tac *map[string]any) string {
	id := str((*tech)["id"])
	if mitreTechniqueID.MatchString(id) {
		return strings.ToUpper(id)
	}
	for _, item := range asArray(x["ttps"]) {
		ttp := asObject(item)
		ttpTech := asObject(ttp["technique"])
		if ttpID := str(ttpTech["id"]); mitreTechniqueID.MatchString(ttpID) {
			*tech = ttpTech
			*tac = asObject(ttp["tactic"])
			return strings.ToUpper(ttpID)
		}
	}
	if id != "" {
		return id
	}
	return unmappedTechniqueID
}

// rawData builds the compact source metadata, with only the keys present in
// the alert (DESIGN §2). Values are copied as decoded (json.Number keeps
// numbers exact).
func rawData(hit Hit, s, x, tech, tac, extra map[string]any) map[string]any {
	raw := map[string]any{"source": sourceName}
	if hit.Index != "" {
		raw["index"] = hit.Index
	}
	copyPresent(raw, "tenantId", s["tenantid"])
	copyPresent(raw, "tenantName", s["tenant_name"])
	copyPresent(raw, "eventScore", s["event_score"])
	copyPresent(raw, "severity", s["severity"])
	copyPresent(raw, "fidelity", s["fidelity"])
	copyPresent(raw, "threatScore", s["threat_score"])
	copyPresent(raw, "status", s["event_status"])
	copyPresent(raw, "writeTime", s["write_time"])
	copyPresent(raw, "eventName", x["name"])
	copyPresent(raw, "killchainStage", x["xdr_killchain_stage"])
	if obj := idAndName(tac); obj != nil {
		raw["tactic"] = obj
	}
	if obj := idAndName(tech); obj != nil {
		raw["technique"] = obj
	}
	for k, v := range extra {
		raw[k] = v
	}
	return raw
}

// idAndName keeps only the id and name keys of a tactic/technique object,
// in their original case. It returns nil when neither is present.
func idAndName(obj map[string]any) map[string]any {
	out := map[string]any{}
	copyPresent(out, "id", obj["id"])
	copyPresent(out, "name", obj["name"])
	if len(out) == 0 {
		return nil
	}
	return out
}

func copyPresent(dst map[string]any, key string, value any) {
	if value != nil {
		dst[key] = value
	}
}

// eventTimeOf returns the first usable value among timestamp, alert_time,
// stellar.alert_time and write_time (epoch ms numbers or date strings).
func eventTimeOf(s map[string]any) (time.Time, bool) {
	candidates := []any{
		s["timestamp"],
		s["alert_time"],
		asObject(s["stellar"])["alert_time"],
		s["write_time"],
	}
	for _, v := range candidates {
		if t, ok := parseTime(v); ok {
			return t, true
		}
	}
	return time.Time{}, false
}

// maxEpochMs is 9999-12-31T23:59:59.999Z, the last instant with a 4-digit year.
const maxEpochMs = 253402300799999

// timeLayouts are the accepted date strings. Layouts without a zone are UTC.
var timeLayouts = []string{
	time.RFC3339Nano,
	"2006-01-02T15:04:05.999999999Z0700",
	"2006-01-02T15:04:05.999999999",
	"2006-01-02 15:04:05.999999999Z07:00",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02",
}

// parseTime accepts an epoch-milliseconds number (or digit string) or a date
// string, and returns the instant in UTC.
func parseTime(v any) (time.Time, bool) {
	if ms, ok := numeric(v); ok {
		return fromEpochMs(ms)
	}
	text, ok := v.(string)
	if !ok {
		return time.Time{}, false
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return time.Time{}, false
	}
	if isDigits(text) {
		ms, err := strconv.ParseFloat(text, 64)
		if err != nil {
			return time.Time{}, false
		}
		return fromEpochMs(ms)
	}
	for _, layout := range timeLayouts {
		if t, err := time.Parse(layout, text); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func fromEpochMs(ms float64) (time.Time, bool) {
	if math.IsNaN(ms) || ms < 0 || ms > maxEpochMs {
		return time.Time{}, false
	}
	return time.UnixMilli(int64(math.Floor(ms))).UTC(), true
}

// epochMs parses an epoch-milliseconds value (number or digit string).
func epochMs(v any) (int64, bool) {
	t, ok := parseTime(v)
	if !ok {
		return 0, false
	}
	return t.UnixMilli(), true
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// alertScore is event_score, else severity, else score (numbers only), else 0.
func alertScore(s map[string]any) float64 {
	for _, key := range []string{"event_score", "severity", "score"} {
		if n, ok := numeric(s[key]); ok {
			return n
		}
	}
	return 0
}

// SeverityFromScore maps a 0-100 Stellar Cyber score to the platform severity:
// >=80 critical, >=60 high, >=40 medium, >=20 low, otherwise info.
func SeverityFromScore(score float64) string {
	switch {
	case score >= 80:
		return string(models.SeverityCritical)
	case score >= 60:
		return string(models.SeverityHigh)
	case score >= 40:
		return string(models.SeverityMedium)
	case score >= 20:
		return string(models.SeverityLow)
	default:
		return string(models.SeverityInfo)
	}
}

// numeric returns v as a finite float64 when it is a JSON number.
func numeric(v any) (float64, bool) {
	var f float64
	switch n := v.(type) {
	case json.Number:
		parsed, err := n.Float64()
		if err != nil {
			return 0, false
		}
		f = parsed
	case float64:
		f = n
	case float32:
		f = float64(n)
	case int:
		f = float64(n)
	case int64:
		f = float64(n)
	case int32:
		f = float64(n)
	default:
		return 0, false
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

// str returns v trimmed when it is a string, else "".
func str(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

func asObject(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func asArray(v any) []any {
	a, _ := v.([]any)
	return a
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// truncateRunes cuts s to at most n characters without splitting a UTF-8 sequence.
func truncateRunes(s string, n int) string {
	count := 0
	for i := range s {
		if count == n {
			return s[:i]
		}
		count++
	}
	return s
}
