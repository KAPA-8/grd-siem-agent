package stellarcyber

import (
	"net/url"
	"testing"
)

func TestBuildAlertsQuery_SpecExample(t *testing.T) {
	got := buildAlertsQuery(rangeClause("timestamp", 1761955200000, 1762560000000), 40, "abc")
	want := `timestamp:[1761955200000 TO 1762560000000} AND event_score:>=40 AND tenantid:"abc" AND NOT event_status:"Ignored"`
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestBuildAlertsQuery_OptionalParts(t *testing.T) {
	got := buildAlertsQuery(rangeClause(fieldWriteTime, 1, 2), 0, "")
	want := `write_time:[1 TO 2} AND NOT event_status:"Ignored"`
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
	got = buildAlertsQuery(rangeClause(fieldWriteTime, 1, 2), 0, `we"ird\tenant`)
	want = `write_time:[1 TO 2} AND tenantid:"we\"ird\\tenant" AND NOT event_status:"Ignored"`
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestMinScoreFor(t *testing.T) {
	tests := map[string]int{"": 0, "info": 0, "low": 20, "Medium": 40, " high ": 60, "critical": 80}
	for in, want := range tests {
		got, err := minScoreFor(in)
		if err != nil || got != want {
			t.Errorf("minScoreFor(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	if _, err := minScoreFor("severe"); err == nil {
		t.Error("expected an error for an unknown severity")
	}
}

func TestEncodeQuery_SpacesAsPercent20(t *testing.T) {
	q := url.Values{"status": {"In Progress"}, "FROM~modified_at": {"5"}, "q": {"a+b"}}
	got := encodeQuery(q)
	want := "FROM~modified_at=5&q=a%2Bb&status=In%20Progress"
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestNormalizeBaseURL(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"acme.stellarcyber.cloud", "https://acme.stellarcyber.cloud"},
		{"  https://acme.stellarcyber.cloud/  ", "https://acme.stellarcyber.cloud"},
		{"https://acme.stellarcyber.cloud/connect/api/v1", "https://acme.stellarcyber.cloud"},
		{"https://10.0.0.5:8443/Connect/API/data/aella-ser-*/_search?q=x#f", "https://10.0.0.5:8443"},
		{"https://dp.local/prefix/connect/api/", "https://dp.local/prefix"},
		{"HTTPS://Acme.StellarCyber.Cloud", "https://Acme.StellarCyber.Cloud"},
		{"https://user:pass@dp.local", "https://dp.local"},
		{"http://dp.local", "http://dp.local"},
	}
	for _, tt := range tests {
		got, err := NormalizeBaseURL(tt.in)
		if err != nil || got != tt.want {
			t.Errorf("NormalizeBaseURL(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}
	for _, bad := range []string{"", "   ", "ftp://dp.local", "https://", "https://:443"} {
		if got, err := NormalizeBaseURL(bad); err == nil {
			t.Errorf("NormalizeBaseURL(%q) = %q, want an error", bad, got)
		}
	}
}
