package stellarcyber

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
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

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{t: t} }

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

// --- mock Stellar Cyber API ---------------------------------------------------

const (
	testEmail     = "api@acme.com"
	testAPIToken  = "all-access-token"
	testScopedKey = "scoped-key-jwt"
)

type mockCase struct {
	ID         string
	Name       string
	Status     string
	TenantID   string
	ModifiedAt int64
	Docs       []Hit
}

type recordedRequest struct {
	Method        string
	Path          string
	Query         url.Values
	Authorization string
	ContentType   string
	BodyLen       int64
}

type injectedFailure struct {
	pathPrefix string
	status     int
	retryAfter string
}

// mockStellar implements the subset of the Stellar Cyber API the collector
// uses: token exchange, URI search on aella-ser-* (Lucene subset of DESIGN §1),
// cases, case alerts and cases/health.
type mockStellar struct {
	t     *testing.T
	clock *fakeClock

	mu            sync.Mutex
	tokenTTL      time.Duration
	omitExp       bool
	legacyBasic   bool // pre-5.x: no token endpoint, Basic on every call
	forbidSearch  bool
	exchangeDelay time.Duration
	tokens        map[string]time.Time
	tokenSeq      int
	tokenCalls    int
	alerts        []Hit
	cases         []mockCase
	failures      []injectedFailure
	requests      []recordedRequest

	// shuffleTies returns records with equal sort values in a different
	// order on every request, as Elasticsearch may across shards/replicas.
	shuffleTies bool
	// ignoreSort returns records in insertion order whatever sort says.
	ignoreSort bool
	rng        *rand.Rand

	// onRequest, when set, runs before each request is served (without the
	// lock held), so tests can change the data between two pages.
	onRequest func(m *mockStellar, r *http.Request)
}

func newMockStellar(t *testing.T, clock *fakeClock) *mockStellar {
	return &mockStellar{t: t, clock: clock, tokenTTL: 10 * time.Minute, tokens: map[string]time.Time{}, rng: rand.New(rand.NewSource(1))}
}

// sortRecords sorts n records by key, honouring ignoreSort and shuffleTies.
func (m *mockStellar) sortRecords(n int, key func(i int) float64, swap func(i, j int), desc bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ignoreSort {
		return
	}
	less := func(i, j int) bool {
		if desc {
			return key(i) > key(j)
		}
		return key(i) < key(j)
	}
	sort.Stable(sortable{n, less, swap})
	if !m.shuffleTies {
		return
	}
	for start := 0; start < n; {
		end := start + 1
		for end < n && key(end) == key(start) {
			end++
		}
		m.rng.Shuffle(end-start, func(i, j int) { swap(start+i, start+j) })
		start = end
	}
}

type sortable struct {
	n    int
	less func(i, j int) bool
	swap func(i, j int)
}

func (s sortable) Len() int           { return s.n }
func (s sortable) Less(i, j int) bool { return s.less(i, j) }
func (s sortable) Swap(i, j int)      { s.swap(i, j) }

func (m *mockStellar) failNext(pathPrefix string, status int, retryAfter string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failures = append(m.failures, injectedFailure{pathPrefix: pathPrefix, status: status, retryAfter: retryAfter})
}

func (m *mockStellar) revokeTokens() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens = map[string]time.Time{}
}

func (m *mockStellar) recorded(pathPrefix string) []recordedRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []recordedRequest
	for _, r := range m.requests {
		if strings.HasPrefix(r.Path, pathPrefix) {
			out = append(out, r)
		}
	}
	return out
}

func (m *mockStellar) resetRequests() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = nil
}

func (m *mockStellar) tokenExchanges() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tokenCalls
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (m *mockStellar) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if m.onRequest != nil {
		m.onRequest(m, r)
	}
	m.mu.Lock()
	m.requests = append(m.requests, recordedRequest{
		Method:        r.Method,
		Path:          r.URL.Path,
		Query:         r.URL.Query(),
		Authorization: r.Header.Get("Authorization"),
		ContentType:   r.Header.Get("Content-Type"),
		BodyLen:       r.ContentLength,
	})
	for i, f := range m.failures {
		if strings.HasPrefix(r.URL.Path, f.pathPrefix) {
			m.failures = append(m.failures[:i], m.failures[i+1:]...)
			m.mu.Unlock()
			if f.retryAfter != "" {
				w.Header().Set("Retry-After", f.retryAfter)
			}
			writeJSON(w, f.status, map[string]string{"error": "injected"})
			return
		}
	}
	m.mu.Unlock()

	if r.Method == http.MethodPost && r.URL.Path == tokenPath {
		m.handleToken(w, r)
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, nil)
		return
	}
	if r.ContentLength > 0 {
		m.t.Errorf("GET %s sent a body", r.URL.Path)
	}
	if r.Header.Get("Accept") != "application/json" {
		m.t.Errorf("GET %s without Accept: application/json", r.URL.Path)
	}
	if !m.authorized(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	switch {
	case r.URL.Path == searchPath:
		m.handleSearch(w, r)
	case r.URL.Path == casesHealthAPI:
		writeJSON(w, http.StatusOK, map[string]any{"data": map[string]string{"status": "working", "version": "6.6.0"}})
	case r.URL.Path == casesPath:
		m.handleCases(w, r)
	case strings.HasPrefix(r.URL.Path, casesPath+"/") && strings.HasSuffix(r.URL.Path, "/alerts"):
		m.handleCaseAlerts(w, r, strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, casesPath+"/"), "/alerts"))
	default:
		writeJSON(w, http.StatusNotFound, nil)
	}
}

func basicHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func (m *mockStellar) handleToken(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	m.tokenCalls++
	legacy, delay := m.legacyBasic, m.exchangeDelay
	m.mu.Unlock()
	if legacy {
		writeJSON(w, http.StatusNotFound, nil)
		return
	}
	if r.ContentLength > 0 {
		m.t.Errorf("access_token request sent a body")
	}
	authz := r.Header.Get("Authorization")
	switch authz {
	case basicHeader(testEmail, testAPIToken):
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			m.t.Errorf("Basic token exchange Content-Type = %q", ct)
		}
	case "Bearer " + testScopedKey:
	default:
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad credentials"})
		return
	}
	if delay > 0 {
		time.Sleep(delay)
	}
	m.mu.Lock()
	m.tokenSeq++
	token := fmt.Sprintf("jwt-%d", m.tokenSeq)
	exp := m.clock.Now().Add(m.tokenTTL)
	m.tokens[token] = exp
	omitExp := m.omitExp
	m.mu.Unlock()
	body := map[string]any{"access_token": token}
	if !omitExp {
		body["exp"] = exp.Unix()
	}
	writeJSON(w, http.StatusOK, body)
}

func (m *mockStellar) authorized(r *http.Request) bool {
	authz := r.Header.Get("Authorization")
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.legacyBasic {
		return authz == basicHeader(testEmail, testAPIToken)
	}
	token, ok := strings.CutPrefix(authz, "Bearer ")
	if !ok {
		return false
	}
	exp, ok := m.tokens[token]
	return ok && m.clock.Now().Before(exp)
}

// --- Lucene subset --------------------------------------------------------------

var (
	reRangeExcl = regexp.MustCompile(`^(\w+):\[(-?\d+) TO (-?\d+)\}$`)
	reRangeIncl = regexp.MustCompile(`^(\w+):\[(-?\d+) TO (-?\d+)\]$`)
	reGTE       = regexp.MustCompile(`^(\w+):>=(-?\d+(?:\.\d+)?)$`)
	reLT        = regexp.MustCompile(`^(\w+):<(-?\d+(?:\.\d+)?)$`)
	rePhrase    = regexp.MustCompile(`^(NOT )?(\w+):"((?:[^"\\]|\\.)*)"$`)
)

type predicate func(source map[string]any) bool

func parseLucene(q string) ([]predicate, error) {
	var preds []predicate
	for _, clause := range strings.Split(q, " AND ") {
		switch {
		case reRangeExcl.MatchString(clause), reRangeIncl.MatchString(clause):
			incl := reRangeIncl.MatchString(clause)
			re := reRangeExcl
			if incl {
				re = reRangeIncl
			}
			m := re.FindStringSubmatch(clause)
			lo, _ := strconv.ParseFloat(m[2], 64)
			hi, _ := strconv.ParseFloat(m[3], 64)
			field := m[1]
			preds = append(preds, func(s map[string]any) bool {
				v, ok := numeric(s[field])
				return ok && v >= lo && (v < hi || (incl && v == hi))
			})
		case reGTE.MatchString(clause):
			m := reGTE.FindStringSubmatch(clause)
			n, _ := strconv.ParseFloat(m[2], 64)
			field := m[1]
			preds = append(preds, func(s map[string]any) bool {
				v, ok := numeric(s[field])
				return ok && v >= n
			})
		case reLT.MatchString(clause):
			m := reLT.FindStringSubmatch(clause)
			n, _ := strconv.ParseFloat(m[2], 64)
			field := m[1]
			preds = append(preds, func(s map[string]any) bool {
				v, ok := numeric(s[field])
				return ok && v < n
			})
		case rePhrase.MatchString(clause):
			m := rePhrase.FindStringSubmatch(clause)
			negate, field := m[1] != "", m[2]
			value := strings.NewReplacer(`\"`, `"`, `\\`, `\`).Replace(m[3])
			preds = append(preds, func(s map[string]any) bool {
				v, ok := s[field].(string)
				match := ok && v == value
				return match != negate
			})
		default:
			return nil, fmt.Errorf("unsupported Lucene clause %q", clause)
		}
	}
	return preds, nil
}

func (m *mockStellar) handleSearch(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	forbid := m.forbidSearch
	m.mu.Unlock()
	if forbid {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	q := r.URL.Query()
	preds, err := parseLucene(q.Get("q"))
	if err != nil {
		m.t.Errorf("search: %v", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	size, from := 10, 0
	if v := q.Get("size"); v != "" {
		size, _ = strconv.Atoi(v)
	}
	if v := q.Get("from"); v != "" {
		from, _ = strconv.Atoi(v)
	}
	if from+size > 10000 || size < 0 || from < 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Result window is too large, from + size must be less than or equal to: [10000]"})
		return
	}

	m.mu.Lock()
	var matched []Hit
	for _, h := range m.alerts {
		ok := true
		for _, p := range preds {
			if !p(h.Source) {
				ok = false
				break
			}
		}
		if ok {
			matched = append(matched, h)
		}
	}
	m.mu.Unlock()

	if sortSpec := q.Get("sort"); sortSpec != "" {
		field, order, _ := strings.Cut(sortSpec, ":")
		m.sortRecords(len(matched), func(i int) float64 {
			v, _ := numeric(matched[i].Source[field])
			return v
		}, func(i, j int) { matched[i], matched[j] = matched[j], matched[i] }, order == "desc")
	}
	total := len(matched)
	page := []Hit{}
	if from < len(matched) {
		page = matched[from:min(len(matched), from+size)]
	}
	writeJSON(w, http.StatusOK, map[string]any{"hits": map[string]any{
		"total": map[string]any{"value": total, "relation": "eq"},
		"hits":  page,
	}})
}

func (m *mockStellar) handleCases(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, skip := 10, 0
	if v := q.Get("limit"); v != "" {
		limit, _ = strconv.Atoi(v)
	}
	if v := q.Get("skip"); v != "" {
		skip, _ = strconv.Atoi(v)
	}
	if limit > 500 || limit < 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be 1..500"})
		return
	}
	var fromMs, toMs *int64
	if v := q.Get("FROM~modified_at"); v != "" {
		n, _ := strconv.ParseInt(v, 10, 64)
		fromMs = &n
	}
	if v := q.Get("TO~modified_at"); v != "" {
		n, _ := strconv.ParseInt(v, 10, 64)
		toMs = &n
	}
	m.mu.Lock()
	var matched []mockCase
	for _, c := range m.cases {
		if fromMs != nil && c.ModifiedAt < *fromMs || toMs != nil && c.ModifiedAt > *toMs {
			continue
		}
		if s := q.Get("status"); s != "" && c.Status != s {
			continue
		}
		if tid := q.Get("tenantid"); tid != "" && c.TenantID != tid {
			continue
		}
		matched = append(matched, c)
	}
	m.mu.Unlock()
	if q.Get("sort") == "modified_at" {
		m.sortRecords(len(matched), func(i int) float64 { return float64(matched[i].ModifiedAt) },
			func(i, j int) { matched[i], matched[j] = matched[j], matched[i] }, q.Get("order") == "desc")
	}

	out := []map[string]any{}
	for i := skip; i < len(matched) && i < skip+limit; i++ {
		c := matched[i]
		out = append(out, map[string]any{
			"_id": c.ID, "name": c.Name, "status": c.Status, "modified_at": c.ModifiedAt,
			"cust_id": c.TenantID, "severity": "High", "score": 70, "size": len(c.Docs),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"cases": out, "total": len(matched)}})
}

func (m *mockStellar) handleCaseAlerts(w http.ResponseWriter, r *http.Request, caseID string) {
	q := r.URL.Query()
	limit, err1 := strconv.Atoi(q.Get("limit"))
	skip, err2 := strconv.Atoi(q.Get("skip"))
	if err1 != nil || err2 != nil || limit < 1 || limit > 50 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "skip and limit (<=50) are required"})
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.cases {
		if c.ID != caseID {
			continue
		}
		docs := []Hit{}
		for i := skip; i < len(c.Docs) && i < skip+limit; i++ {
			docs = append(docs, c.Docs[i])
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"docs": docs}})
		return
	}
	writeJSON(w, http.StatusNotFound, nil)
}

// --- helpers ---------------------------------------------------------------------

// testBase is 2026-10-30T12:00:00Z.
var testBase = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

// alertHit builds an aella-ser hit ingested at writeTime.
func alertHit(id string, writeTime int64, score float64) Hit {
	return Hit{
		Index: "stellar-index-v1-ser-org-tenantA-2026.10.30-000001",
		ID:    id,
		Source: map[string]any{
			"timestamp":    writeTime - 60_000,
			"write_time":   writeTime,
			"tenantid":     "tenantA",
			"event_score":  score,
			"event_status": "New",
			"srcip":        "10.0.0.1",
			"xdr_event": map[string]any{
				"display_name": "Alert " + id,
				"tactic":       map[string]any{"id": "TA0006", "name": "Credential Access"},
				"technique":    map[string]any{"id": "T1110", "name": "Brute Force"},
			},
		},
	}
}

type testEnv struct {
	clock  *fakeClock
	mock   *mockStellar
	server *httptest.Server
	coll   *Collector
	sleeps []time.Duration
}

// newSaaSEnv starts a plain-HTTP mock and a SaaS collector against it.
func newSaaSEnv(t *testing.T, mutate func(*settings, *config.SyncConfig)) *testEnv {
	t.Helper()
	env := &testEnv{clock: newFakeClock(testBase)}
	env.mock = newMockStellar(t, env.clock)
	env.server = httptest.NewServer(env.mock)
	t.Cleanup(env.server.Close)

	s := settings{
		baseURL:    env.server.URL,
		deployment: deploymentSaaS,
		dataSource: dataSourceAlerts,
		authMode:   authModeAPIToken,
		username:   testEmail,
		apiKey:     testAPIToken,
	}
	syncCfg := config.SyncConfig{LookbackDays: 7, MaxAlertsPerSync: 1000, Filters: config.Filters{MinSeverity: "info"}}
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
	e.coll.client.auth.now = e.clock.Now
	var mu sync.Mutex
	e.coll.client.sleep = func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		e.sleeps = append(e.sleeps, d)
		mu.Unlock()
		return ctx.Err()
	}
}

func (e *testEnv) addAlerts(hits ...Hit) {
	e.mock.mu.Lock()
	defer e.mock.mu.Unlock()
	e.mock.alerts = append(e.mock.alerts, hits...)
}

func (e *testEnv) addCases(cases ...mockCase) {
	e.mock.mu.Lock()
	defer e.mock.mu.Unlock()
	e.mock.cases = append(e.mock.cases, cases...)
}
