package fortisiem

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/grd-platform/grd-siem-agent/internal/config"
)

// --- fake clock ---------------------------------------------------------------

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// --- mock FortiSIEM API -------------------------------------------------------

// mockProfile selects the behaviour of a FortiSIEM version.
type mockProfile int

const (
	// profileCloud is FortiSIEM Cloud as observed (DESIGN §6): Basic and
	// OAuth, GET on the token endpoint answers an HTML error page, envelope
	// {start,total,pages,sizePerPage,data,queryId}, vocabulary as words.
	profileCloud mockProfile = iota
	// profile74 is on-prem 7.4.x (DESIGN §7): Basic only, the token endpoint
	// answers 404, envelope {start,total,data} with total as a string, and
	// the documented integer codes.
	profile74
)

const (
	testOrg      = "super"
	testUser     = "apiuser"
	testPassword = `p:a$s"w'o@r/d`
	testClientID = "synthetic-client"
	testSecret   = "synthetic-client-secret"
)

type recordedRequest struct {
	Method        string
	Path          string
	Authorization string
	ContentType   string
	Query         incidentQuery
}

type injectedFailure struct {
	status     int
	retryAfter string
	body       string
}

// mockIncident is one stored incident. Fields hold the FortiSIEM Cloud
// vocabulary; the 7.4 profile renders the integer codes instead.
type mockIncident struct {
	ID        int64
	FirstSeen int64
	LastSeen  int64
	Category  string // Security, Change, Availability
	Status    string // Active, Auto Cleared, Cleared Manually, System Cleared
	Reso      string // None, Open, True Positive, False Positive, In Progress
	Severity  int
	Customer  string
	CustID    int64
}

var (
	categoryCodes = map[string]int{"Availability": 1, "Change": 3, "Security": 4}
	statusCodes   = map[string]int{"Active": 0, "Auto Cleared": 1, "Cleared Manually": 2, "System Cleared": 3}
	resoCodes     = map[string]int{"None": 0, "Open": 1, "True Positive": 2, "False Positive": 3, "In Progress": 4}
)

type mockFortiSIEM struct {
	t       *testing.T
	clock   *fakeClock
	profile mockProfile

	mu sync.Mutex
	// inclusiveEnd answers size+1 incidents per page, as FortiSIEM Cloud does.
	inclusiveEnd bool
	// tokenPostStatus, when set, is the answer to POST on the token endpoint
	// (405 to exercise the GET fallback).
	tokenPostStatus int
	// tokenTransient400 answers the next N token POSTs with the transient
	// 400 "Invalid input parameters" seen on FortiSIEM Cloud.
	tokenTransient400 int
	// tokenGetJSON makes GET on the token endpoint answer a token.
	tokenGetJSON bool
	// rejectOrderByLastSeen answers 400 to orderBy incidentLastSeen.
	rejectOrderByLastSeen bool
	// rejectOrderByIncidentID answers 400 to orderBy incidentId.
	rejectOrderByIncidentID bool
	// htmlIncidents answers the incident query with an HTML page (200).
	htmlIncidents bool
	// unstable reproduces FortiSIEM's unstable paging (DESIGN §10): on every
	// call the incidents that share the sort key come in a new order and a
	// page after the first starts up to unstableShift positions before or
	// after start, so a paged read repeats some incidents and skips others.
	// A page at start 0 still holds the first incidents of the window.
	unstable      bool
	unstableShift int
	rng           *rand.Rand
	// onQuery, when set, runs before each incident query is answered with
	// the number of incident queries so far (1-based).
	onQuery    func(n int)
	queryCount int
	tokenTTL   time.Duration
	tokens     map[string]time.Time
	tokenSeq   int
	tokenCalls int
	incidents  []mockIncident
	failures   []injectedFailure
	requests   []recordedRequest
}

func newMockFortiSIEM(t *testing.T, clock *fakeClock, profile mockProfile) *mockFortiSIEM {
	return &mockFortiSIEM{t: t, clock: clock, profile: profile, tokenTTL: 24 * time.Hour, tokens: map[string]time.Time{}}
}

// setUnstable turns on the unstable paging with a fixed seed.
func (m *mockFortiSIEM) setUnstable(seed int64, shift int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unstable, m.unstableShift, m.rng = true, shift, rand.New(rand.NewSource(seed))
}

func (m *mockFortiSIEM) add(incs ...mockIncident) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.incidents = append(m.incidents, incs...)
}

// update changes a stored incident in place.
func (m *mockFortiSIEM) update(id int64, fn func(*mockIncident)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.incidents {
		if m.incidents[i].ID == id {
			fn(&m.incidents[i])
			return
		}
	}
	m.t.Fatalf("no incident %d", id)
}

func (m *mockFortiSIEM) failNext(status int, retryAfter string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failures = append(m.failures, injectedFailure{status: status, retryAfter: retryAfter})
}

func (m *mockFortiSIEM) revokeTokens() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens = map[string]time.Time{}
}

func (m *mockFortiSIEM) recorded(path string) []recordedRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []recordedRequest
	for _, r := range m.requests {
		if r.Path == path {
			out = append(out, r)
		}
	}
	return out
}

func (m *mockFortiSIEM) resetRequests() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = nil
}

func (m *mockFortiSIEM) tokenExchanges() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tokenCalls
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

const tomcatErrorPage = `<!doctype html><html lang="en"><head><title>HTTP Status 500 – Internal Server Error</title></head><body><h1>HTTP Status 500</h1></body></html>`

func (m *mockFortiSIEM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rec := recordedRequest{Method: r.Method, Path: r.URL.Path, Authorization: r.Header.Get("Authorization"), ContentType: r.Header.Get("Content-Type")}
	if r.URL.Path == incidentPath && r.Method == http.MethodPost {
		if err := json.NewDecoder(r.Body).Decode(&rec.Query); err != nil {
			m.t.Errorf("incident query body: %v", err)
		}
	}
	m.mu.Lock()
	m.requests = append(m.requests, rec)
	var failure *injectedFailure
	if len(m.failures) > 0 {
		failure = &m.failures[0]
		m.failures = m.failures[1:]
	}
	m.mu.Unlock()

	if failure != nil {
		if failure.retryAfter != "" {
			w.Header().Set("Retry-After", failure.retryAfter)
		}
		writeJSON(w, failure.status, map[string]string{"error": "injected"})
		return
	}

	switch r.URL.Path {
	case tokenPath:
		m.handleToken(w, r)
	case incidentPath:
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, nil)
			return
		}
		if !m.authorized(r) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("<html><body>401 Unauthorized</body></html>"))
			return
		}
		m.handleIncidents(w, rec.Query)
	default:
		writeJSON(w, http.StatusNotFound, nil)
	}
}

// authorized accepts Basic "super/apiuser:<password>" (the organization
// prefix is required) or a live bearer token (Cloud only).
func (m *mockFortiSIEM) authorized(r *http.Request) bool {
	authz := r.Header.Get("Authorization")
	if raw, ok := strings.CutPrefix(authz, "Basic "); ok {
		decoded, err := base64.StdEncoding.DecodeString(raw)
		return err == nil && string(decoded) == testOrg+"/"+testUser+":"+testPassword
	}
	if token, ok := strings.CutPrefix(authz, "Bearer "); ok && m.profile == profileCloud {
		m.mu.Lock()
		defer m.mu.Unlock()
		expiry, live := m.tokens[token]
		return live && m.clock.Now().Before(expiry)
	}
	return false
}

func (m *mockFortiSIEM) handleToken(w http.ResponseWriter, r *http.Request) {
	if m.profile == profile74 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Not Found"})
		return
	}
	m.mu.Lock()
	postStatus, getJSON := m.tokenPostStatus, m.tokenGetJSON
	m.mu.Unlock()

	var values map[string][]string
	switch r.Method {
	case http.MethodPost:
		m.mu.Lock()
		transient := m.tokenTransient400 > 0
		if transient {
			m.tokenTransient400--
		}
		m.mu.Unlock()
		if transient {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("Invalid input parameters"))
			return
		}
		if postStatus != 0 {
			writeJSON(w, postStatus, nil)
			return
		}
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			writeJSON(w, http.StatusUnsupportedMediaType, nil)
			return
		}
		if err := r.ParseForm(); err != nil {
			writeJSON(w, http.StatusBadRequest, nil)
			return
		}
		values = r.PostForm
	case http.MethodGet:
		if !getJSON {
			w.Header().Set("Content-Type", "text/html;charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(tomcatErrorPage))
			return
		}
		values = r.URL.Query()
	default:
		writeJSON(w, http.StatusMethodNotAllowed, nil)
		return
	}
	get := func(k string) string {
		if v := values[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	if get("grant_type") != "client_credentials" || get("client_id") != testClientID || get("client_secret") != testSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	m.mu.Lock()
	m.tokenCalls++
	m.tokenSeq++
	token := fmt.Sprintf("synthetic-token-%d", m.tokenSeq)
	m.tokens[token] = m.clock.Now().Add(m.tokenTTL)
	ttl := int(m.tokenTTL / time.Second)
	m.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"access_token": token, "expires_in": ttl, "token_type": "Bearer"})
}

func (m *mockFortiSIEM) handleIncidents(w http.ResponseWriter, q incidentQuery) {
	m.mu.Lock()
	m.queryCount++
	n, hook := m.queryCount, m.onQuery
	m.mu.Unlock()
	if hook != nil {
		hook(n)
	}

	m.mu.Lock()
	rejectLastSeen, rejectID, html, inclusive := m.rejectOrderByLastSeen, m.rejectOrderByIncidentID, m.htmlIncidents, m.inclusiveEnd
	var matched []mockIncident
	for _, inc := range m.incidents {
		if inc.LastSeen >= q.TimeFrom && inc.LastSeen <= q.TimeTo { // FortiSIEM filters on lastSeen
			matched = append(matched, inc)
		}
	}
	m.mu.Unlock()

	if html {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>FortiSIEM login</body></html>"))
		return
	}
	key := func(inc mockIncident) int64 { return inc.FirstSeen }
	switch q.OrderBy {
	case orderByLastSeen:
		if rejectLastSeen {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid orderBy"})
			return
		}
		key = func(inc mockIncident) int64 { return inc.LastSeen }
	case orderByIncidentID:
		if rejectID {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid orderBy"})
			return
		}
		key = func(inc mockIncident) int64 { return inc.ID }
	case orderByFirstSeen:
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid orderBy"})
		return
	}
	sort.SliceStable(matched, func(i, j int) bool {
		if q.Descending {
			return key(matched[i]) > key(matched[j])
		}
		return key(matched[i]) < key(matched[j])
	})
	size := q.Size
	if size > 1000 {
		size = 1000
	}
	first := q.Start
	m.mu.Lock()
	if m.unstable {
		shuffleTies(matched, key, m.rng)
		if first > 0 && m.unstableShift > 0 {
			first = max(first+m.rng.Intn(2*m.unstableShift+1)-m.unstableShift, 0)
		}
	}
	m.mu.Unlock()
	end := first + size
	if inclusive {
		end++
	}
	data := []any{}
	for i := first; i < len(matched) && i < end; i++ {
		data = append(data, m.render(matched[i]))
	}
	if m.profile == profile74 {
		writeJSON(w, http.StatusOK, map[string]any{"start": q.Start, "total": strconv.Itoa(len(matched)), "data": data})
		return
	}
	pages := 0
	if size > 0 {
		pages = (len(matched) + size - 1) / size
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"start": q.Start, "total": len(matched), "pages": pages, "sizePerPage": len(data),
		"data": data, "queryId": "pub_inc_query_synthetic",
	})
}

// shuffleTies reorders the runs of incidents that share the sort key.
func shuffleTies(incs []mockIncident, key func(mockIncident) int64, rng *rand.Rand) {
	for i := 0; i < len(incs); {
		j := i + 1
		for j < len(incs) && key(incs[j]) == key(incs[i]) {
			j++
		}
		run := incs[i:j]
		rng.Shuffle(len(run), func(a, b int) { run[a], run[b] = run[b], run[a] })
		i = j
	}
}

// render shapes an incident as the profile's FortiSIEM version returns it.
func (m *mockFortiSIEM) render(inc mockIncident) map[string]any {
	out := map[string]any{
		"incidentId":         inc.ID,
		"incidentTitle":      fmt.Sprintf("Synthetic incident %d", inc.ID),
		"eventType":          "PH_RULE_SYNTH",
		"eventName":          "Synthetic Rule",
		"eventSeverity":      inc.Severity,
		"eventSeverityCat":   "MEDIUM",
		"incidentFirstSeen":  inc.FirstSeen,
		"incidentLastSeen":   inc.LastSeen,
		"attackTactic":       "Credential Access",
		"attackTechnique":    `[{"name": "Brute Force", "techniqueid": "T1110"}]`,
		"incidentSrc":        "srcIpAddr:198.51.100.7, srcGeoCountry:Synthland, ",
		"incidentTarget":     "destIpAddr:10.0.0.5, hostName:srv-synth-01, ",
		"incidentRptDevName": "collector-synth-01",
		"count":              3,
		"customer":           inc.Customer,
		"phCustId":           inc.CustID,
	}
	if m.profile == profile74 {
		out["phIncidentCategory"] = categoryCodes[inc.Category]
		out["incidentStatus"] = statusCodes[inc.Status]
		out["incidentReso"] = resoCodes[inc.Reso]
		out["eventSeverity"] = strconv.Itoa(inc.Severity) // 7.4 may send numbers as strings
		return out
	}
	out["phIncidentCategory"] = inc.Category
	out["incidentStatus"] = inc.Status
	out["incidentReso"] = inc.Reso
	out["custId"] = inc.CustID
	return out
}

// --- helpers ---------------------------------------------------------------------

// testBase is 2026-11-24T12:00:00Z.
var testBase = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

func ms(t time.Time) int64 { return t.UnixMilli() }

// securityIncident is an active Security incident first and last seen at at.
func securityIncident(id int64, at time.Time) mockIncident {
	return mockIncident{ID: id, FirstSeen: ms(at), LastSeen: ms(at), Category: "Security", Status: "Active", Reso: "Open", Severity: 7, Customer: "Super", CustID: 1}
}

type testEnv struct {
	clock  *fakeClock
	mock   *mockFortiSIEM
	server *httptest.Server
	coll   *Collector
	sleeps []time.Duration
}

func basicSettings(baseURL, deployment string) settings {
	return settings{
		baseURL: baseURL, deployment: deployment, authMode: authModeBasic,
		organization: testOrg, username: testUser, password: testPassword, securityOnly: true,
	}
}

func oauthSettings(baseURL string) settings {
	return settings{baseURL: baseURL, deployment: deploymentCloud, authMode: authModeOAuth, clientID: testClientID, clientSecret: testSecret, securityOnly: true}
}

// newEnv starts a plain-HTTP mock of the profile and a collector against it.
func newEnv(t *testing.T, profile mockProfile, mutate func(*settings, *config.SyncConfig)) *testEnv {
	t.Helper()
	env := &testEnv{clock: &fakeClock{t: testBase}}
	env.mock = newMockFortiSIEM(t, env.clock, profile)
	env.server = httptest.NewServer(env.mock)
	t.Cleanup(env.server.Close)

	s := basicSettings(env.server.URL, deploymentOnPrem)
	if profile == profileCloud {
		s = oauthSettings(env.server.URL)
	}
	syncCfg := config.SyncConfig{LookbackDays: 7, MaxAlertsPerSync: 1000, StatusRefreshHours: 6}
	if mutate != nil {
		mutate(&s, &syncCfg)
	}
	coll, err := newCollectorWith(s, env.server.Client(), syncCfg)
	if err != nil {
		t.Fatalf("newCollectorWith: %v", err)
	}
	env.coll = coll
	env.useClock()
	return env
}

// useClock wires the fake clock and a sleep recorder into the collector.
func (e *testEnv) useClock() {
	e.coll.now = e.clock.Now
	e.coll.client.now = e.clock.Now
	if ts, ok := e.coll.client.auth.(*oauthTokenSource); ok {
		ts.now = e.clock.Now
	}
	var mu sync.Mutex
	e.coll.client.sleep = func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		e.sleeps = append(e.sleeps, d)
		mu.Unlock()
		return ctx.Err()
	}
}

// collect runs one cycle and fails the test on error.
func (e *testEnv) collect(t *testing.T, checkpoint string) (batchIDs []string, b batchView) {
	t.Helper()
	batch, err := e.coll.Collect(context.Background(), checkpoint)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	view := batchView{checkpoint: batch.Checkpoint, fetched: batch.Fetched, statusOnly: map[string]bool{}, fairExcluded: map[string]bool{}, status: map[string]string{}}
	for _, tpl := range batch.Templates {
		batchIDs = append(batchIDs, tpl.ExternalID)
		view.statusOnly[tpl.ExternalID] = tpl.StatusOnly
		view.fairExcluded[tpl.ExternalID] = tpl.FairExcluded != nil && *tpl.FairExcluded
		view.status[tpl.ExternalID] = tpl.SourceStatus
	}
	view.from, view.to = batch.WindowFrom, batch.WindowTo
	return batchIDs, view
}

type batchView struct {
	checkpoint   string
	fetched      int
	from, to     time.Time
	statusOnly   map[string]bool
	fairExcluded map[string]bool
	status       map[string]string
}

func idsOf(ids ...int64) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = strconv.FormatInt(id, 10)
	}
	return out
}

func sortedCopy(ids []string) []string {
	out := append([]string(nil), ids...)
	sort.Slice(out, func(i, j int) bool {
		a, _ := strconv.ParseInt(out[i], 10, 64)
		b, _ := strconv.ParseInt(out[j], 10, 64)
		return a < b
	})
	return out
}

func sameIDs(t *testing.T, label string, got, want []string) {
	t.Helper()
	g, w := sortedCopy(got), sortedCopy(want)
	if strings.Join(g, ",") != strings.Join(w, ",") {
		t.Errorf("%s: ids = %v, want %v", label, g, w)
	}
}
