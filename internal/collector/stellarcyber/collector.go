// Package stellarcyber collects alerts from Stellar Cyber Open XDR (SaaS or
// on-prem Data Processor) for the GRD platform.
//
// Two data sources are supported:
//   - alerts: the aella-ser-* alert index through /connect/api/data (needs a
//     root All-Access token, or a scoped key on 6.3+).
//   - cases: /connect/api/v1/cases plus /cases/{id}/alerts (works with scoped keys).
//
// Collection is incremental on ingestion time (write_time for alerts,
// modified_at for cases) with a stability lag, and the checkpoint keeps the
// IDs seen at the last timestamp so ties are never lost or duplicated.
package stellarcyber

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/grd-platform/grd-siem-agent/internal/collector"
	"github.com/grd-platform/grd-siem-agent/internal/config"
	"github.com/grd-platform/grd-siem-agent/internal/siemhttp"
)

// Name is the siem.type of this collector.
const Name = "stellar_cyber"

const (
	deploymentSaaS   = "saas"
	deploymentOnPrem = "onprem"
	dataSourceAlerts = "alerts"
	dataSourceCases  = "cases"

	checkpointVersion = 1

	// stabilityLag keeps the window's upper bound behind "now" so documents
	// still being written are picked up by the next cycle instead of missed.
	stabilityLag = 120 * time.Second

	alertsPageSize     = 500   // max size per _search request
	maxResultWindow    = 10000 // from + size limit of the alert index
	casesPageSize      = 100
	maxCasesLimit      = 500 // /cases limit
	caseAlertsPageSize = 50  // /cases/{id}/alerts limit

	defaultMaxAlerts    = 1000
	defaultLookbackDays = 7

	// maxCheckpointSkew rejects checkpoints too far in the future (corrupt
	// file or a clock that jumped), which would otherwise stall collection.
	maxCheckpointSkew = 24 * time.Hour
)

func init() {
	collector.Register(Name, New, ValidateConfig)
}

// settings is the validated, defaulted Stellar Cyber configuration.
type settings struct {
	baseURL    string
	deployment string
	dataSource string
	authMode   string
	username   string
	apiKey     string
	tenantID   string
}

func lowerOr(value, fallback string) string {
	if v := strings.ToLower(strings.TrimSpace(value)); v != "" {
		return v
	}
	return fallback
}

// resolveSettings applies defaults (deployment saas, data_source alerts,
// auth_mode api_token) and validates the siem section.
func resolveSettings(cfg config.SIEMConfig) (settings, error) {
	s := settings{
		deployment: lowerOr(cfg.Deployment, deploymentSaaS),
		dataSource: lowerOr(cfg.DataSource, dataSourceAlerts),
		authMode:   lowerOr(cfg.Credentials.AuthMode, authModeAPIToken),
		username:   strings.TrimSpace(cfg.Credentials.Username), // case-sensitive
		apiKey:     strings.TrimSpace(cfg.Credentials.APIKey),
		tenantID:   strings.TrimSpace(cfg.Credentials.TenantID),
	}

	var errs []error
	if s.deployment != deploymentSaaS && s.deployment != deploymentOnPrem {
		errs = append(errs, fmt.Errorf("siem.deployment must be saas or onprem (got %q)", cfg.Deployment))
	}
	if s.dataSource != dataSourceAlerts && s.dataSource != dataSourceCases {
		errs = append(errs, fmt.Errorf("siem.data_source must be alerts or cases (got %q)", cfg.DataSource))
	}
	switch s.authMode {
	case authModeAPIToken:
		if s.username == "" {
			errs = append(errs, errors.New("siem.credentials.username (the API account email) is required with auth_mode api_token"))
		} else if !strings.Contains(s.username, "@") {
			errs = append(errs, fmt.Errorf("siem.credentials.username must be the API account email address (got %q)", s.username))
		}
	case authModeScopedKey:
	default:
		errs = append(errs, fmt.Errorf("siem.credentials.auth_mode must be api_token or scoped_key (got %q)", cfg.Credentials.AuthMode))
	}
	if s.apiKey == "" {
		errs = append(errs, errors.New("siem.credentials.api_key is required"))
	}

	baseURL, err := NormalizeBaseURL(cfg.APIURL)
	if err != nil {
		errs = append(errs, err)
	} else if s.deployment == deploymentSaaS && strings.HasPrefix(baseURL, "http://") {
		errs = append(errs, fmt.Errorf("siem.api_url must use https for Stellar Cyber SaaS (got %q)", cfg.APIURL))
	}
	s.baseURL = baseURL

	return s, errors.Join(errs...)
}

// ValidateConfig validates the Stellar Cyber part of the configuration.
func ValidateConfig(cfg config.SIEMConfig) error {
	_, err := resolveSettings(cfg)
	return err
}

// Collector implements collector.Collector for Stellar Cyber.
type Collector struct {
	settings  settings
	client    *Client
	minScore  int
	maxAlerts int
	lookback  time.Duration
	now       func() time.Time

	// Paging limits (constants; fields so tests can shrink them).
	pageSize           int
	maxResultWindow    int
	casesPageSize      int
	maxCasesLimit      int
	caseAlertsPageSize int
}

var _ collector.Collector = (*Collector)(nil)

// New creates a Stellar Cyber collector. SaaS always verifies the server
// certificate; on-prem honours validate_ssl and ca_cert_file.
func New(cfg config.SIEMConfig, syncCfg config.SyncConfig) (collector.Collector, error) {
	c, err := newCollector(cfg, syncCfg)
	if err != nil {
		return nil, err // an untyped nil, not a nil *Collector inside the interface
	}
	return c, nil
}

func newCollector(cfg config.SIEMConfig, syncCfg config.SyncConfig) (*Collector, error) {
	s, err := resolveSettings(cfg)
	if err != nil {
		return nil, err
	}

	skipVerify := false
	if !cfg.Credentials.ValidateSSL {
		if s.deployment == deploymentOnPrem {
			skipVerify = true
			log.Warn().Msg("stellar cyber: TLS certificate verification is disabled (validate_ssl: false); prefer ca_cert_file")
		} else {
			log.Warn().Msg("stellar cyber: validate_ssl: false is ignored for SaaS; certificates are always verified")
		}
	}
	httpClient, err := siemhttp.NewClient(siemhttp.Options{
		InsecureSkipVerify: skipVerify,
		CAFile:             cfg.Credentials.CACertFile,
		Timeout:            requestTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("stellar cyber: %w", err)
	}
	return newCollectorWith(s, httpClient, syncCfg)
}

// newCollectorWith builds a collector from resolved settings and an HTTP client.
func newCollectorWith(s settings, httpClient *http.Client, syncCfg config.SyncConfig) (*Collector, error) {
	minScore, err := minScoreFor(syncCfg.Filters.MinSeverity)
	if err != nil {
		return nil, err
	}
	maxAlerts := syncCfg.MaxAlertsPerSync
	if maxAlerts <= 0 {
		maxAlerts = defaultMaxAlerts
	}
	maxAlerts = min(maxAlerts, maxResultWindow)
	lookbackDays := syncCfg.LookbackDays
	if lookbackDays <= 0 {
		lookbackDays = defaultLookbackDays
	}

	now := time.Now
	return &Collector{
		settings:           s,
		client:             newClient(s.baseURL, httpClient, s, now),
		minScore:           minScore,
		maxAlerts:          maxAlerts,
		lookback:           time.Duration(lookbackDays) * 24 * time.Hour,
		now:                now,
		pageSize:           alertsPageSize,
		maxResultWindow:    maxResultWindow,
		casesPageSize:      casesPageSize,
		maxCasesLimit:      maxCasesLimit,
		caseAlertsPageSize: caseAlertsPageSize,
	}, nil
}

// Name returns the SIEM type.
func (c *Collector) Name() string { return Name }

// Init exchanges the credential for a token and checks access to the data
// source. The platform version (from /cases/health) is logged when available.
func (c *Collector) Init(ctx context.Context) error {
	if err := c.probe(ctx); err != nil {
		return err
	}
	event := log.Info().
		Str("url", c.settings.baseURL).
		Str("deployment", c.settings.deployment).
		Str("data_source", c.settings.dataSource).
		Str("auth_mode", c.settings.authMode)
	if h, err := c.client.health(ctx); err == nil && h.Data.Version != "" {
		event = event.Str("version", h.Data.Version)
	}
	event.Msg("connected to Stellar Cyber")
	return nil
}

// HealthCheck verifies the credential and access to the data source.
func (c *Collector) HealthCheck(ctx context.Context) error {
	return c.probe(ctx)
}

func (c *Collector) probe(ctx context.Context) error {
	var err error
	if c.settings.dataSource == dataSourceCases {
		_, err = c.client.listCases(ctx, url.Values{"limit": {"1"}})
	} else {
		err = c.client.probeAlerts(ctx)
	}
	return err
}

// Close releases idle connections.
func (c *Collector) Close() error {
	c.client.httpClient.CloseIdleConnections()
	return nil
}

// checkpointState is the persisted checkpoint:
// {"v":1,"mode":"alerts"|"cases","ts":<ms>,"ids":[...]}, where ts is the
// last write_time (alerts) or modified_at (cases) delivered and ids are the
// alert or case IDs already delivered at exactly that ts.
type checkpointState struct {
	V    int      `json:"v"`
	Mode string   `json:"mode"`
	TS   int64    `json:"ts"`
	IDs  []string `json:"ids"`
}

// parseCheckpoint accepts only a checkpoint of this collector's mode. Anything
// else (empty, a QRadar epoch, the other mode, a corrupt or far-future value)
// makes the collector fall back to the lookback window.
func parseCheckpoint(raw, mode string, now time.Time) (checkpointState, bool) {
	if strings.TrimSpace(raw) == "" {
		return checkpointState{}, false
	}
	var cp checkpointState
	if err := json.Unmarshal([]byte(raw), &cp); err != nil ||
		cp.V != checkpointVersion || cp.Mode != mode || cp.TS <= 0 {
		log.Warn().Str("checkpoint", raw).Str("mode", mode).Msg("stellar cyber: ignoring checkpoint from another format or mode; using lookback")
		return checkpointState{}, false
	}
	if cp.TS > now.Add(maxCheckpointSkew).UnixMilli() {
		log.Warn().Int64("ts", cp.TS).Msg("stellar cyber: checkpoint is in the future; using lookback")
		return checkpointState{}, false
	}
	return cp, true
}

// checkpointTracker computes the next checkpoint: the highest timestamp seen
// and the IDs delivered at exactly that timestamp.
type checkpointTracker struct {
	mode    string
	ts      int64
	ids     map[string]struct{}
	changed bool
}

// newCheckpointTracker starts from the current checkpoint, or from the
// window's lower bound when there is none (so a foreign checkpoint is
// replaced even when nothing new is found).
func newCheckpointTracker(mode string, cp checkpointState, valid bool, lower int64) *checkpointTracker {
	t := &checkpointTracker{mode: mode, ts: lower, ids: map[string]struct{}{}, changed: !valid}
	if valid {
		t.ts = cp.TS
		for _, id := range cp.IDs {
			t.ids[id] = struct{}{}
		}
	}
	return t
}

func (t *checkpointTracker) observe(ts int64, id string) {
	switch {
	case ts > t.ts:
		t.ts = ts
		t.ids = map[string]struct{}{id: {}}
		t.changed = true
	case ts == t.ts:
		if _, ok := t.ids[id]; !ok {
			t.ids[id] = struct{}{}
			t.changed = true
		}
	}
}

// skipPast moves the checkpoint just past ts, dropping the ID list.
func (t *checkpointTracker) skipPast(ts int64) {
	t.ts = ts + 1
	t.ids = map[string]struct{}{}
	t.changed = true
}

// encode returns the new checkpoint, or current when nothing changed.
func (t *checkpointTracker) encode(current string) string {
	if !t.changed {
		return current
	}
	ids := make([]string, 0, len(t.ids))
	for id := range t.ids {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	data, _ := json.Marshal(checkpointState{V: checkpointVersion, Mode: t.mode, TS: t.ts, IDs: ids})
	return string(data)
}

// Collect fetches the alerts ingested since the checkpoint. The window is
// [checkpoint ts or now-lookback, now-stabilityLag).
func (c *Collector) Collect(ctx context.Context, checkpoint string) (collector.Batch, error) {
	now := c.now()
	mode := c.settings.dataSource
	cp, valid := parseCheckpoint(checkpoint, mode, now)

	lower := now.Add(-c.lookback).UnixMilli()
	if valid {
		lower = cp.TS
	}
	upper := now.Add(-stabilityLag).UnixMilli()

	batch := collector.Batch{
		Checkpoint: checkpoint,
		WindowFrom: time.UnixMilli(lower).UTC(),
		WindowTo:   time.UnixMilli(upper).UTC(),
	}
	tracker := newCheckpointTracker(mode, cp, valid, lower)

	if lower < upper {
		var err error
		if mode == dataSourceCases {
			err = c.collectCases(ctx, &batch, cp, valid, tracker, lower, upper)
		} else {
			err = c.collectAlerts(ctx, &batch, cp, valid, tracker, lower, upper)
		}
		if err != nil {
			return collector.Batch{}, err
		}
	}
	batch.Checkpoint = tracker.encode(checkpoint)

	log.Info().
		Str("data_source", mode).
		Time("from", batch.WindowFrom).
		Time("to", batch.WindowTo).
		Int("fetched", batch.Fetched).
		Int("alerts", len(batch.Templates)).
		Msg("stellar cyber: collection complete")
	return batch, nil
}

// collectAlerts pages through write_time:[lower TO upper} sorted ascending,
// until the window is exhausted or max_alerts_per_sync is reached.
//
// Paging is keyset, not offset: every page is a new query anchored at the
// highest write_time read so far (write_time:[anchor TO upper}, from=0), and
// the hits already read at exactly that write_time (the checkpoint's IDs on
// the first page) are skipped by ID. With from/size offsets, an alert that
// leaves the result set while paging (marked Ignored, say) shifts every later
// alert one place to the left, so the alert at the next page boundary is
// never read while the checkpoint moves past it. An anchored query has no
// boundary to shift, and the from+size <= 10000 window only matters when one
// millisecond holds more alerts than a page.
//
// Keyset paging relies on the server sorting by write_time; a page that comes
// back unsorted fails the cycle instead of silently losing alerts. Alerts
// that share one write_time come back first, in any order, so asking for
// the ones already read on top of a full page always makes progress. Only a
// millisecond holding a full page or more of alerts is paged by offset
// (that part is exact only if the server returns ties in a stable order).
func (c *Collector) collectAlerts(ctx context.Context, batch *collector.Batch, cp checkpointState, valid bool, tracker *checkpointTracker, lower, upper int64) error {
	// IDs an earlier cycle delivered at the checkpoint ts.
	delivered := map[string]struct{}{}
	if valid {
		for _, id := range cp.IDs {
			delivered[id] = struct{}{}
		}
	}
	anchor := lower
	read := map[string]struct{}{}         // hits read this cycle at write_time == anchor (index/_id)
	reread := 0                           // hits at the anchor that offset pages returned again
	unpositioned := map[string]struct{}{} // hits read without a usable write_time (index/_id)
	seen := map[string]struct{}{}         // alert IDs read this cycle
	accepted := 0

	for accepted < c.maxAlerts && anchor < upper {
		// The hits at the anchor that will come back first: the ones read on
		// earlier pages, plus the checkpoint's while the anchor is its ts.
		known := len(read)
		if valid && anchor == cp.TS {
			known += len(delivered)
		}
		want := min(c.pageSize, c.maxAlerts-accepted)
		from, size := 0, min(c.pageSize, want+known)
		byOffset := known >= c.pageSize
		if byOffset {
			// A page cannot get past the hits already read at this write_time:
			// page through that millisecond by offset instead.
			from = known + reread
			size = min(want, c.maxResultWindow-from)
		}
		if size <= 0 {
			// Every reachable result at this write_time was already read: more
			// alerts share one millisecond than the search window allows.
			// Step past it rather than stall forever.
			log.Error().
				Int64("write_time", anchor).
				Int("window", c.maxResultWindow).
				Msg("stellar cyber: more alerts share one write_time than the search window allows; skipping the rest of that millisecond")
			tracker.skipPast(anchor)
			anchor++
			read, reread = map[string]struct{}{}, 0
			continue
		}

		pageLower := anchor
		query := buildAlertsQuery(rangeClause(fieldWriteTime, pageLower, upper), c.minScore, c.settings.tenantID)
		res, err := c.client.searchAlerts(ctx, query, from, size)
		if err != nil {
			return fmt.Errorf("searching alerts (write_time >= %d, from=%d): %w", pageLower, from, err)
		}
		hits := res.Hits.Hits
		progressed, pastUpper := false, false
		rereadBefore := reread
		prev := pageLower
		for _, hit := range hits {
			if accepted >= c.maxAlerts {
				break // the rest is collected next cycle
			}
			if hit.ID == "" {
				log.Warn().Str("index", hit.Index).Msg("stellar cyber: skipping alert without _id")
				continue
			}
			key := hit.Index + "/" + hit.ID
			writeTime, positioned := epochMs(hit.Source["write_time"])
			if positioned {
				if writeTime < pageLower {
					continue // outside the queried range
				}
				if writeTime >= upper {
					pastUpper = true // sorted: nothing after it is in the window
					break
				}
				if writeTime < prev {
					return fmt.Errorf("searching alerts: results are not sorted by write_time (%d after %d); the server ignored sort=%s:asc, which incremental collection requires", writeTime, prev, fieldWriteTime)
				}
				prev = writeTime
				if writeTime > anchor {
					// Sorted: every hit before this write_time has been read.
					anchor = writeTime
					read, reread = map[string]struct{}{}, 0
				} else {
					_, done := read[key]
					if _, inCheckpoint := delivered[hit.ID]; inCheckpoint && valid && writeTime == cp.TS {
						done = true // delivered by an earlier cycle
					}
					if done {
						if byOffset && anchor == pageLower {
							reread++ // the next offset page starts after it
						}
						continue
					}
				}
				read[key] = struct{}{}
			} else {
				if _, done := unpositioned[key]; done {
					continue
				}
				unpositioned[key] = struct{}{}
			}
			progressed = true

			batch.Fetched++
			if _, dup := seen[hit.ID]; dup {
				batch.DuplicatesRemoved++
				continue
			}
			seen[hit.ID] = struct{}{}
			accepted++
			if positioned {
				tracker.observe(writeTime, hit.ID)
			}
			c.appendMapped(batch, hit, nil)
		}
		if pastUpper || len(hits) < size {
			break // window exhausted
		}
		if !progressed && reread == rereadBefore {
			return fmt.Errorf("searching alerts: no progress at write_time %d (a full page of alerts already read); the server may ignore the query or sort", anchor)
		}
	}
	return nil
}

// collectCases lists the cases modified in [lower, upper) once per status,
// then fetches each case's alerts (50 per page) in modified_at order. Cases
// are never split: once max_alerts_per_sync alerts have been read no new case
// is started, and the checkpoint stops at the last case processed.
func (c *Collector) collectCases(ctx context.Context, batch *collector.Batch, cp checkpointState, valid bool, tracker *checkpointTracker, lower, upper int64) error {
	cases, err := c.listModifiedCases(ctx, lower, upper)
	if err != nil {
		return err
	}
	sort.Slice(cases, func(i, j int) bool {
		if cases[i].ModifiedAt.ms != cases[j].ModifiedAt.ms {
			return cases[i].ModifiedAt.ms < cases[j].ModifiedAt.ms
		}
		return cases[i].ID < cases[j].ID
	})

	skip := map[string]struct{}{}
	if valid {
		for _, id := range cp.IDs {
			skip[id] = struct{}{}
		}
	}
	seenDocs := map[string]struct{}{}

	for _, cs := range cases {
		modifiedAt := cs.ModifiedAt.ms
		if modifiedAt < lower || modifiedAt >= upper {
			continue
		}
		if _, done := skip[cs.ID]; done && valid && modifiedAt == cp.TS {
			continue
		}
		if batch.Fetched >= c.maxAlerts {
			log.Info().Int("max_alerts", c.maxAlerts).Msg("stellar cyber: max_alerts_per_sync reached; remaining cases are collected next cycle")
			break
		}

		docs, err := c.allCaseAlerts(ctx, cs.ID)
		if err != nil {
			return fmt.Errorf("fetching alerts of case %s: %w", cs.ID, err)
		}
		extra := map[string]any{"caseId": cs.ID}
		if name := strings.TrimSpace(cs.Name); name != "" {
			extra["caseName"] = name
		}
		for _, doc := range docs {
			if doc.ID == "" || doc.Source == nil || (doc.Found != nil && !*doc.Found) {
				continue
			}
			batch.Fetched++
			if _, dup := seenDocs[doc.ID]; dup {
				batch.DuplicatesRemoved++
				continue
			}
			seenDocs[doc.ID] = struct{}{}
			if !c.passesFilters(doc.Source) {
				continue
			}
			c.appendMapped(batch, doc, extra)
		}
		tracker.observe(modifiedAt, cs.ID)
	}
	return nil
}

// passesFilters applies to case alerts the filters the alerts mode sends to
// the server: NOT event_status:"Ignored" and event_score:>=min.
func (c *Collector) passesFilters(source map[string]any) bool {
	if strings.EqualFold(str(source["event_status"]), ignoredStatus) {
		return false
	}
	if c.minScore > 0 {
		score, ok := numeric(source["event_score"])
		if !ok || score < float64(c.minScore) {
			return false
		}
	}
	return true
}

// listModifiedCases queries each status separately and merges the results.
func (c *Collector) listModifiedCases(ctx context.Context, lower, upper int64) ([]stellarCase, error) {
	var all []stellarCase
	seen := map[string]struct{}{}
	for _, status := range caseStatuses {
		cases, err := c.listStatusCases(ctx, status, lower, upper)
		if err != nil {
			return nil, err
		}
		for _, cs := range cases {
			if _, dup := seen[cs.ID]; dup {
				continue // its status changed between two queries
			}
			seen[cs.ID] = struct{}{}
			all = append(all, cs)
		}
	}
	return all, nil
}

// errCasesUnsorted reports a cases page that is not sorted by modified_at.
var errCasesUnsorted = errors.New("cases are not sorted by modified_at")

// listStatusCases lists every case of one status modified in [lower, upper).
// It pages by keyset and falls back to skip offsets when the server does not
// sort by modified_at (the cases are sorted locally afterwards, so the
// listing itself does not depend on the order).
func (c *Collector) listStatusCases(ctx context.Context, status string, lower, upper int64) ([]stellarCase, error) {
	cases, err := c.pageStatusCases(ctx, status, lower, upper, true)
	if errors.Is(err, errCasesUnsorted) {
		log.Warn().Str("status", status).Msg("stellar cyber: the server ignored sort=modified_at; listing these cases by offset")
		return c.pageStatusCases(ctx, status, lower, upper, false)
	}
	return cases, err
}

// pageStatusCases pages through one status's cases.
//
// With keyset paging every page is a new query anchored at the highest
// modified_at listed so far (FROM~modified_at=anchor, skip=0), asking for the
// cases already listed at exactly that modified_at on top of a full page.
// With skip offsets, a listed case that is modified meanwhile (its new
// modified_at is past the window) shifts the later cases one place to the
// left, so the case at the next page boundary is never listed, and the
// checkpoint then moves past it for good.
func (c *Collector) pageStatusCases(ctx context.Context, status string, lower, upper int64, keyset bool) ([]stellarCase, error) {
	var out []stellarCase
	listed := map[string]struct{}{}
	anchor := lower
	atAnchor := map[string]struct{}{} // cases listed with modified_at == anchor
	reread := 0                       // cases at the anchor that skip pages returned again
	offset := 0

	for {
		from, skip, limit := lower, offset, c.casesPageSize
		bySkip := false
		if keyset {
			from, skip, limit = anchor, 0, c.casesPageSize+len(atAnchor)
			if limit > c.maxCasesLimit {
				// More cases share one modified_at than a page can hold on top
				// of a full page: page through that millisecond by skip.
				bySkip = true
				skip, limit = len(atAnchor)+reread, c.casesPageSize
			}
		}
		query := url.Values{}
		query.Set("FROM~"+fieldModifiedAt, strconv.FormatInt(from, 10))
		query.Set("TO~"+fieldModifiedAt, strconv.FormatInt(upper, 10))
		query.Set("sort", fieldModifiedAt)
		query.Set("order", "asc")
		query.Set("limit", strconv.Itoa(limit))
		query.Set("skip", strconv.Itoa(skip))
		query.Set("status", status)
		if c.settings.tenantID != "" {
			query.Set("tenantid", c.settings.tenantID)
		}
		page, err := c.client.listCases(ctx, query)
		if err != nil {
			return nil, fmt.Errorf("listing %q cases: %w", status, err)
		}

		fresh := 0
		pastUpper := false
		rereadBefore := reread
		prev := from
		for _, cs := range page.Data.Cases {
			if cs.ID == "" || !cs.ModifiedAt.ok {
				log.Warn().Str("case", cs.ID).Msg("stellar cyber: skipping case without _id or modified_at")
				continue
			}
			modifiedAt := cs.ModifiedAt.ms
			if keyset {
				if modifiedAt < prev {
					return nil, errCasesUnsorted
				}
				prev = modifiedAt
				if modifiedAt >= upper {
					pastUpper = true // sorted: nothing after it is in the window
					break
				}
				if modifiedAt > anchor {
					anchor = modifiedAt
					atAnchor, reread = map[string]struct{}{}, 0
				} else if _, again := atAnchor[cs.ID]; again && bySkip && anchor == from {
					reread++ // the next skip page starts after it
				}
				atAnchor[cs.ID] = struct{}{}
			}
			if _, dup := listed[cs.ID]; dup {
				continue
			}
			listed[cs.ID] = struct{}{}
			fresh++
			out = append(out, cs)
		}

		n := len(page.Data.Cases)
		offset += n
		if pastUpper || n < limit {
			break
		}
		if total := page.total(); total > 0 && int64(skip+n) >= total {
			break
		}
		if fresh == 0 && reread == rereadBefore {
			// A full page of cases already listed: going on would loop, and
			// stopping early could let the checkpoint pass unlisted cases.
			return nil, fmt.Errorf("listing %q cases: no progress (a full page of cases already listed at modified_at %d); the server may ignore skip or FROM~%s", status, anchor, fieldModifiedAt)
		}
	}
	return out, nil
}

// allCaseAlerts pages /cases/{id}/alerts until a short page.
func (c *Collector) allCaseAlerts(ctx context.Context, caseID string) ([]Hit, error) {
	var docs []Hit
	seen := map[string]struct{}{}
	for skip := 0; ; skip += c.caseAlertsPageSize {
		page, err := c.client.caseAlerts(ctx, caseID, skip, c.caseAlertsPageSize)
		if err != nil {
			return nil, err
		}
		fresh := 0
		for _, doc := range page {
			if _, dup := seen[doc.ID]; !dup {
				seen[doc.ID] = struct{}{}
				fresh++
			}
		}
		docs = append(docs, page...)
		if len(page) < c.caseAlertsPageSize {
			return docs, nil
		}
		if fresh == 0 {
			log.Warn().Str("case", caseID).Msg("stellar cyber: case alerts page repeated (skip ignored?); stopping")
			return docs, nil
		}
	}
}

func (c *Collector) appendMapped(batch *collector.Batch, hit Hit, extra map[string]any) {
	template, _, err := MapHit(hit, extra)
	if err != nil {
		log.Warn().Str("id", hit.ID).Err(err).Msg("stellar cyber: skipping alert")
		return
	}
	batch.Templates = append(batch.Templates, template)
}
