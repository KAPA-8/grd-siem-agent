// Package fortisiem collects incidents from FortiSIEM (FortiSIEM Cloud or an
// on-prem Supervisor, 6.3+) for the GRD platform through
// POST /phoenix/rest/pub/incident.
//
// Authentication is Basic "<organization>/<user>:<password>" (every version;
// the only one on 7.4.x and earlier) or OAuth client credentials (7.5+,
// FortiSIEM Cloud).
//
// FortiSIEM filters timeFrom/timeTo on incidentLastSeen, so collection is
// incremental on incidentLastSeen: every cycle asks for the incidents seen
// since the checkpoint minus a 10-minute overlap, sorted by incidentLastSeen,
// and the checkpoint keeps the highest incidentLastSeen delivered plus the
// IDs delivered at exactly that millisecond. An incident first seen before
// the lookback horizon is sent as statusOnly (the platform only refreshes the
// status of an alert it already has). Every status_refresh_hours the whole
// lookback window is read again, since an analyst can resolve an incident
// (false positive...) without its incidentLastSeen changing.
package fortisiem

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/grd-platform/grd-siem-agent/internal/collector"
	"github.com/grd-platform/grd-siem-agent/internal/config"
	"github.com/grd-platform/grd-siem-agent/internal/siemhttp"
)

// Name is the siem.type of this collector.
const Name = "fortisiem"

const (
	deploymentCloud  = "cloud"
	deploymentOnPrem = "onprem"

	checkpointVersion = 1
	checkpointMode    = "incidents"

	// pageSize is the incidents asked per page: FortiSIEM caps size near 1000
	// and may return size+1 items (inclusive end), so pages are advanced by
	// pageSize and deduplicated by incidentId.
	pageSize = 500
	// maxPages bounds one pass whatever the server answers.
	maxPages = 400

	// overlap re-reads the end of the previous window, for incidents that
	// became visible after their incidentLastSeen.
	overlap = 10 * time.Minute

	defaultMaxAlerts    = 1000
	defaultLookbackDays = 7

	// hardLimit bounds a pass that cannot stop early: the status sweep, and a
	// pass whose results are not sorted by incidentLastSeen.
	hardLimit = config.MaxAlertsPerSyncLimit

	// maxCheckpointSkew rejects checkpoints too far in the future (corrupt
	// file or a clock that jumped), which would otherwise stall collection.
	maxCheckpointSkew = 24 * time.Hour

	maxTenantLength = 255
)

func init() {
	collector.Register(Name, New, ValidateConfig)
}

// settings is the validated, defaulted FortiSIEM configuration.
type settings struct {
	baseURL      string
	deployment   string
	authMode     string
	organization string
	username     string
	password     string
	clientID     string
	clientSecret string
	tenantID     string
	securityOnly bool
}

func lowerOr(value, fallback string) string {
	if v := strings.ToLower(strings.TrimSpace(value)); v != "" {
		return v
	}
	return fallback
}

// resolveSettings applies the defaults (deployment cloud, auth_mode basic,
// organization super) and validates the siem section.
func resolveSettings(cfg config.SIEMConfig) (settings, error) {
	cred := cfg.Credentials
	s := settings{
		deployment:   lowerOr(cfg.Deployment, deploymentCloud),
		authMode:     lowerOr(cred.AuthMode, authModeBasic),
		organization: strings.TrimSpace(cred.Organization),
		username:     strings.TrimSpace(cred.Username),
		password:     cred.Password,
		clientID:     strings.TrimSpace(cred.ClientID),
		clientSecret: strings.TrimSpace(cred.ClientSecret),
		tenantID:     strings.TrimSpace(cred.TenantID),
		securityOnly: cred.SecurityOnly,
	}

	var errs []error
	if s.deployment != deploymentCloud && s.deployment != deploymentOnPrem {
		errs = append(errs, fmt.Errorf("siem.deployment debe ser cloud u onprem (valor: %q)", cfg.Deployment))
	}
	switch s.authMode {
	case authModeBasic:
		if s.username == "" {
			errs = append(errs, errors.New("siem.credentials.username es obligatorio con auth_mode basic (el usuario de FortiSIEM, sin el prefijo de organización)"))
		} else if strings.Contains(s.username, ":") {
			errs = append(errs, errors.New("siem.credentials.username no puede contener ':' (separa usuario y contraseña en la autenticación Basic)"))
		}
		if strings.ContainsAny(s.organization, "/:") {
			errs = append(errs, fmt.Errorf("siem.credentials.organization no puede contener '/' ni ':' (valor: %q); usa solo el nombre de la organización, p. ej. super", s.organization))
		}
		if s.password == "" {
			errs = append(errs, fmt.Errorf("siem.credentials.password es obligatorio con auth_mode basic (o define %s o %s)",
				config.EnvVarNames("siem.credentials.password")[1], config.EnvVarName("siem.credentials.password")))
		}
	case authModeOAuth:
		if s.clientID == "" {
			errs = append(errs, errors.New("siem.credentials.client_id es obligatorio con auth_mode oauth"))
		}
		if s.clientSecret == "" {
			errs = append(errs, fmt.Errorf("siem.credentials.client_secret es obligatorio con auth_mode oauth (o define %s o %s)",
				config.EnvVarNames("siem.credentials.client_secret")[1], config.EnvVarName("siem.credentials.client_secret")))
		}
	default:
		errs = append(errs, fmt.Errorf("siem.credentials.auth_mode debe ser basic u oauth (valor: %q); FortiSIEM 7.4 o anterior solo admite basic", cred.AuthMode))
	}
	if len([]rune(s.tenantID)) > maxTenantLength {
		errs = append(errs, fmt.Errorf("siem.credentials.tenant_id admite como máximo %d caracteres", maxTenantLength))
	}

	baseURL, err := NormalizeBaseURL(cfg.APIURL)
	if err != nil {
		errs = append(errs, err)
	} else if s.deployment == deploymentCloud && strings.HasPrefix(baseURL, "http://") {
		errs = append(errs, fmt.Errorf("siem.api_url debe usar https con FortiSIEM Cloud (valor: %q)", cfg.APIURL))
	}
	s.baseURL = baseURL

	return s, errors.Join(errs...)
}

// ValidateConfig validates the FortiSIEM part of the configuration.
func ValidateConfig(cfg config.SIEMConfig) error {
	_, err := resolveSettings(cfg)
	return err
}

// Collector implements collector.Collector for FortiSIEM.
type Collector struct {
	settings      settings
	client        *Client
	minSeverity   string
	maxAlerts     int
	lookback      time.Duration
	statusRefresh time.Duration
	now           func() time.Time

	// orderBy is orderByLastSeen unless the server rejected it.
	orderBy string
	// Paging limits (constants; fields so tests can shrink them).
	pageSize int
	maxPages int

	// pending and confirmed remember the incidents delivered in the overlap
	// window (see Collect), so they are not posted again every cycle.
	pending   *deliveryMemo
	confirmed *deliveryMemo
}

var _ collector.Collector = (*Collector)(nil)

// New creates a FortiSIEM collector. FortiSIEM Cloud always verifies the
// server certificate; on-prem honours validate_ssl and ca_cert_file.
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
			log.Warn().Msg("fortisiem: TLS certificate verification is disabled (validate_ssl: false); prefer ca_cert_file with the Supervisor certificate")
		} else {
			log.Warn().Msg("fortisiem: validate_ssl: false is ignored for FortiSIEM Cloud; certificates are always verified")
		}
	}
	httpClient, err := siemhttp.NewClient(siemhttp.Options{
		InsecureSkipVerify: skipVerify,
		CAFile:             cfg.Credentials.CACertFile,
		Timeout:            requestTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("fortisiem: %w", err)
	}
	return newCollectorWith(s, httpClient, syncCfg)
}

// newCollectorWith builds a collector from resolved settings and an HTTP client.
func newCollectorWith(s settings, httpClient *http.Client, syncCfg config.SyncConfig) (*Collector, error) {
	minSeverity, err := minSeverityFor(syncCfg.Filters.MinSeverity)
	if err != nil {
		return nil, err
	}
	maxAlerts := syncCfg.MaxAlertsPerSync
	if maxAlerts <= 0 {
		maxAlerts = defaultMaxAlerts
	}
	maxAlerts = min(maxAlerts, hardLimit)
	lookbackDays := syncCfg.LookbackDays
	if lookbackDays <= 0 {
		lookbackDays = defaultLookbackDays
	}
	now := time.Now
	return &Collector{
		settings:      s,
		client:        newClient(s.baseURL, httpClient, s, now),
		minSeverity:   minSeverity,
		maxAlerts:     maxAlerts,
		lookback:      time.Duration(lookbackDays) * 24 * time.Hour,
		statusRefresh: time.Duration(max(syncCfg.StatusRefreshHours, 0)) * time.Hour,
		now:           now,
		orderBy:       orderByLastSeen,
		pageSize:      pageSize,
		maxPages:      maxPages,
	}, nil
}

// Name returns the SIEM type.
func (c *Collector) Name() string { return Name }

// Init authenticates and runs a one-incident query over the last hour.
func (c *Collector) Init(ctx context.Context) error {
	page, err := c.probe(ctx, time.Hour)
	if err != nil {
		return err
	}
	event := log.Info().
		Str("url", c.settings.baseURL).
		Str("deployment", c.settings.deployment).
		Str("auth_mode", c.settings.authMode).
		Bool("security_only", c.settings.securityOnly)
	if c.settings.tenantID != "" {
		event = event.Str("tenant_id", c.settings.tenantID)
	}
	if page.HasTotal {
		event = event.Int64("incidents_last_hour", page.Total)
	}
	event.Msg("connected to FortiSIEM")
	return nil
}

// HealthCheck verifies the credentials and access to the incident API.
func (c *Collector) HealthCheck(ctx context.Context) error {
	_, err := c.probe(ctx, time.Hour)
	return err
}

// TestConnection authenticates, queries one incident of the last 24 hours
// and describes the result (grd-siem-agent test-siem). Nothing is sent to
// the platform.
func (c *Collector) TestConnection(ctx context.Context) (string, error) {
	page, err := c.probe(ctx, 24*time.Hour)
	if err != nil {
		return "", err
	}
	total := "desconocido"
	if page.HasTotal {
		total = fmt.Sprint(page.Total)
	} else if page.Items > 0 {
		total = "al menos 1"
	} else {
		total = "0"
	}
	return fmt.Sprintf("conexión correcta con FortiSIEM (%s, auth_mode %s): incidentes con actividad en las últimas 24 h: %s (todas las categorías y organizaciones visibles)",
		c.settings.deployment, c.settings.authMode, total), nil
}

func (c *Collector) probe(ctx context.Context, span time.Duration) (*incidentPage, error) {
	now := c.now()
	return c.query(ctx, 0, 1, now.Add(-span).UnixMilli(), now.UnixMilli())
}

// query runs one incident page. A server that rejects sorting by
// incidentLastSeen (HTTP 400) is asked again sorted by incidentFirstSeen,
// which every version documents, and keeps that sort from then on.
func (c *Collector) query(ctx context.Context, start, size int, from, to int64) (*incidentPage, error) {
	page, err := c.client.queryIncidents(ctx, newIncidentQuery(start, size, from, to, c.orderBy))
	var apiErr *APIError
	if err != nil && c.orderBy == orderByLastSeen && errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusBadRequest {
		log.Warn().Err(err).Msg("fortisiem: the server rejected orderBy incidentLastSeen; sorting by incidentFirstSeen (each cycle then reads its whole window)")
		c.orderBy = orderByFirstSeen
		return c.client.queryIncidents(ctx, newIncidentQuery(start, size, from, to, c.orderBy))
	}
	return page, err
}

// Close releases idle connections.
func (c *Collector) Close() error {
	c.client.httpClient.CloseIdleConnections()
	return nil
}

// --- checkpoint -----------------------------------------------------------------

// checkpointState is the persisted checkpoint:
// {"v":1,"mode":"incidents","ts":<ms>,"ids":[...],"sweep":<ms>}, where ts is
// the highest incidentLastSeen delivered, ids the incidents delivered at
// exactly that ts and sweep the time of the last status sweep.
type checkpointState struct {
	V     int      `json:"v"`
	Mode  string   `json:"mode"`
	TS    int64    `json:"ts"`
	IDs   []string `json:"ids"`
	Sweep int64    `json:"sweep,omitempty"`
}

// parseCheckpoint accepts only a checkpoint of this collector. Anything else
// (empty, another collector's, corrupt or far in the future) makes the
// collector fall back to the lookback window.
func parseCheckpoint(raw string, now time.Time) (checkpointState, bool) {
	if strings.TrimSpace(raw) == "" {
		return checkpointState{}, false
	}
	var cp checkpointState
	if err := json.Unmarshal([]byte(raw), &cp); err != nil ||
		cp.V != checkpointVersion || cp.Mode != checkpointMode || cp.TS <= 0 {
		log.Warn().Str("checkpoint", raw).Msg("fortisiem: ignoring checkpoint from another format; using lookback")
		return checkpointState{}, false
	}
	if cp.TS > now.Add(maxCheckpointSkew).UnixMilli() {
		log.Warn().Int64("ts", cp.TS).Msg("fortisiem: checkpoint is in the future; using lookback")
		return checkpointState{}, false
	}
	return cp, true
}

// checkpointTracker computes the next checkpoint: the highest incidentLastSeen
// processed and the IDs processed at exactly that timestamp.
type checkpointTracker struct {
	initial checkpointState
	ts      int64
	ids     map[string]struct{}
	sweep   int64
	changed bool
}

// newCheckpointTracker starts from the current checkpoint, or from the
// window's lower bound when there is none (so a foreign checkpoint is
// replaced even when nothing is found).
func newCheckpointTracker(cp checkpointState, valid bool, lower int64) *checkpointTracker {
	t := &checkpointTracker{initial: cp, ts: lower, ids: map[string]struct{}{}, changed: !valid}
	if valid {
		t.ts, t.sweep = cp.TS, cp.Sweep
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

// restore drops the progress observed in this cycle (the window could not
// be read safely), keeping the sweep time.
func (t *checkpointTracker) restore(valid bool, lower int64) {
	sweep := t.sweep
	*t = *newCheckpointTracker(t.initial, valid, lower)
	if sweep != t.sweep {
		t.sweep, t.changed = sweep, true
	}
}

func (t *checkpointTracker) setSweep(ms int64) {
	if t.sweep != ms {
		t.sweep = ms
		t.changed = true
	}
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
	data, _ := json.Marshal(checkpointState{V: checkpointVersion, Mode: checkpointMode, TS: t.ts, IDs: ids, Sweep: t.sweep})
	return string(data)
}

// deliveryMemo maps incidentId -> incidentLastSeen of the incidents a batch
// delivered in the overlap window. It applies once the agent comes back
// with checkpoint (which it does only after delivering that batch).
type deliveryMemo struct {
	checkpoint string
	lastSeen   map[string]int64
}

// --- collection -----------------------------------------------------------------

// pass is one paged read of [from, to] (incidentLastSeen).
type pass struct {
	name  string
	from  int64
	to    int64
	limit int
	opts  MapOptions
	// exclude holds the incidents already in the batch.
	exclude map[string]struct{}
	// skip reports an incident already delivered with this incidentLastSeen.
	skip func(id string, lastSeen int64, hasLastSeen bool) bool
	// observe, when set, positions the checkpoint.
	observe func(lastSeen int64, id string)
	// emitted, when set, receives the incidents added to the batch.
	emitted func(id string, lastSeen int64, hasLastSeen bool)
}

type passResult struct {
	accepted  int
	skipped   int
	truncated bool
	unsorted  bool
}

// Collect fetches the incidents seen since the checkpoint.
//
// The query window is [checkpoint ts - 10 min, now] on incidentLastSeen (the
// lookback window without a checkpoint) and is the batch window. Incidents
// already delivered with the same incidentLastSeen (the checkpoint's IDs, and
// the overlap delivered by the previous batch) are skipped. Incidents first
// seen before now - lookback_days are sent as statusOnly. When a status sweep
// is due, [now - lookback_days, now] is read again and every incident not
// already in the batch is added.
func (c *Collector) Collect(ctx context.Context, checkpoint string) (collector.Batch, error) {
	now := c.now()
	nowMs := now.UnixMilli()
	cp, valid := parseCheckpoint(checkpoint, now)

	horizon := now.Add(-c.lookback).UnixMilli()
	from := horizon
	if valid {
		from = cp.TS - overlap.Milliseconds()
	}
	to := nowMs
	from = min(from, to)

	batch := collector.Batch{
		Checkpoint: checkpoint,
		WindowFrom: time.UnixMilli(from).UTC(),
		WindowTo:   time.UnixMilli(to).UTC(),
	}
	tracker := newCheckpointTracker(cp, valid, from)

	// The overlap delivered by the batch the agent has just confirmed.
	if c.pending != nil && c.pending.checkpoint == checkpoint {
		c.confirmed = c.pending
	}
	c.pending = nil
	var known map[string]int64
	if c.confirmed != nil && c.confirmed.checkpoint == checkpoint {
		known = c.confirmed.lastSeen
	}
	checkpointIDs := map[string]struct{}{}
	if valid {
		for _, id := range cp.IDs {
			checkpointIDs[id] = struct{}{}
		}
	}

	opts := c.mapOptions(&Window{From: horizon, To: to})
	inBatch := map[string]struct{}{}
	delivered := map[string]int64{}
	incremental := pass{
		name:  "incremental",
		from:  from,
		to:    to,
		limit: c.maxAlerts,
		opts:  opts,
		skip: func(id string, lastSeen int64, hasLastSeen bool) bool {
			if !hasLastSeen {
				return false
			}
			if v, ok := known[id]; ok && v == lastSeen {
				return true
			}
			_, done := checkpointIDs[id]
			return done && valid && lastSeen == cp.TS
		},
		observe: tracker.observe,
		emitted: func(id string, lastSeen int64, hasLastSeen bool) {
			inBatch[id] = struct{}{}
			if hasLastSeen {
				delivered[id] = lastSeen
			}
		},
	}
	res, err := c.runPass(ctx, &batch, incremental)
	if err != nil {
		return collector.Batch{}, err
	}
	if res.truncated {
		if res.unsorted {
			// Without the incidentLastSeen order, the incidents not read may be
			// older than the ones read: the checkpoint cannot move.
			log.Error().Int("limit", hardLimit).Msg("fortisiem: the window holds more incidents than one unsorted pass can read; the checkpoint does not advance (lower sync.lookback_days)")
			tracker.restore(valid, from)
		} else {
			log.Info().Int("max_alerts", c.maxAlerts).Msg("fortisiem: max_alerts_per_sync reached; the rest is collected next cycle")
		}
	}

	if c.statusRefresh > 0 {
		switch {
		case !valid:
			// The first cycle reads the whole lookback window already.
			tracker.setSweep(nowMs)
		case nowMs-cp.Sweep >= c.statusRefresh.Milliseconds():
			sweep := pass{name: "status sweep", from: min(horizon, to), to: to, limit: hardLimit, opts: opts, exclude: inBatch}
			sres, err := c.runPass(ctx, &batch, sweep)
			if err != nil {
				return collector.Batch{}, fmt.Errorf("barrido de estado: %w", err)
			}
			if sres.truncated {
				log.Warn().Int("limit", hardLimit).Msg("fortisiem: the status sweep read its maximum of incidents; the rest is refreshed in later sweeps")
			}
			log.Info().Int("incidents", sres.accepted).Msg("fortisiem: status sweep complete")
			tracker.setSweep(nowMs)
		}
	}

	batch.Checkpoint = tracker.encode(checkpoint)
	if batch.Checkpoint != checkpoint {
		c.pending = c.rememberOverlap(batch.Checkpoint, tracker.ts, known, delivered)
	}

	statusOnly, excluded := 0, 0
	for _, t := range batch.Templates {
		if t.StatusOnly {
			statusOnly++
		}
		if t.FairExcluded != nil && *t.FairExcluded {
			excluded++
		}
	}
	log.Info().
		Time("from", batch.WindowFrom).
		Time("to", batch.WindowTo).
		Int("fetched", batch.Fetched).
		Int("skipped_delivered", res.skipped).
		Int("alerts", len(batch.Templates)).
		Int("status_only", statusOnly).
		Int("false_positive", excluded).
		Msg("fortisiem: collection complete")
	return batch, nil
}

// rememberOverlap keeps the incidents delivered with incidentLastSeen within
// the next cycle's overlap.
func (c *Collector) rememberOverlap(checkpoint string, ts int64, known, delivered map[string]int64) *deliveryMemo {
	floor := ts - overlap.Milliseconds()
	memo := &deliveryMemo{checkpoint: checkpoint, lastSeen: map[string]int64{}}
	for _, m := range []map[string]int64{known, delivered} {
		for id, lastSeen := range m {
			if lastSeen >= floor {
				memo.lastSeen[id] = lastSeen
			}
		}
	}
	return memo
}

func (c *Collector) mapOptions(window *Window) MapOptions {
	return MapOptions{
		SecurityOnly: c.settings.securityOnly,
		TenantID:     c.settings.tenantID,
		MinSeverity:  c.minSeverity,
		Window:       window,
	}
}

// runPass pages through [p.from, p.to] sorted by incidentLastSeen ascending.
//
// Pages advance by pageSize (FortiSIEM may answer pageSize+1 items) and are
// deduplicated by incidentId; the pass ends on an empty page, once start
// reaches total, or after maxPages. Once p.limit incidents were accepted the
// pass stops (truncated); the checkpoint then stops at the last incident
// processed, which is safe only while the server sorts by incidentLastSeen:
// a pass that finds the order broken (or a server that cannot sort by it)
// reads up to hardLimit incidents instead.
func (c *Collector) runPass(ctx context.Context, batch *collector.Batch, p pass) (passResult, error) {
	var res passResult
	limit := p.limit
	seen := map[string]struct{}{}
	prev := int64(-1)

	for page, start := 0, 0; ; page, start = page+1, start+c.pageSize {
		if page >= c.maxPages {
			log.Warn().Str("pass", p.name).Int("pages", page).Msg("fortisiem: page limit reached; stopping this pass")
			res.truncated = true
			return res, nil
		}
		pg, err := c.query(ctx, start, c.pageSize, p.from, p.to)
		if err != nil {
			return res, fmt.Errorf("consultando incidentes (start=%d): %w", start, err)
		}
		if c.orderBy != orderByLastSeen && !res.unsorted {
			res.unsorted = true
			limit = max(limit, hardLimit)
		}
		if pg.Items == 0 {
			return res, nil
		}
		if pg.Invalid > 0 {
			log.Warn().Int("items", pg.Invalid).Msg("fortisiem: skipping data[] items that are not objects")
			batch.Fetched += pg.Invalid
		}
		for _, inc := range pg.Data {
			id := incidentID(inc["incidentId"])
			if id == "" {
				batch.Fetched++
				log.Warn().Msg("fortisiem: skipping incident without incidentId")
				continue
			}
			if _, dup := seen[id]; dup {
				continue // repeated at a page boundary
			}
			seen[id] = struct{}{}

			lastSeen, hasLastSeen := epochMs(inc["incidentLastSeen"])
			if hasLastSeen && c.orderBy == orderByLastSeen {
				if lastSeen < prev && !res.unsorted {
					log.Warn().Int64("incidentLastSeen", lastSeen).Int64("previous", prev).Msg("fortisiem: incidents are not sorted by incidentLastSeen; reading the whole window")
					res.unsorted = true
					limit = max(limit, hardLimit)
				}
				prev = max(prev, lastSeen)
			}
			if res.accepted >= limit {
				res.truncated = true
				return res, nil
			}
			if _, done := p.exclude[id]; done {
				continue
			}
			if p.observe != nil && hasLastSeen {
				p.observe(min(lastSeen, p.to), id)
			}
			if p.skip != nil && p.skip(id, lastSeen, hasLastSeen) {
				res.skipped++
				continue
			}

			batch.Fetched++
			template, err := MapIncident(inc, p.opts)
			if err != nil {
				if !errors.Is(err, errFiltered) {
					log.Warn().Str("incident", id).Err(err).Msg("fortisiem: skipping incident")
				}
				continue
			}
			res.accepted++
			batch.Templates = append(batch.Templates, template)
			if p.emitted != nil {
				p.emitted(id, lastSeen, hasLastSeen)
			}
		}
		if pg.HasTotal && int64(start+c.pageSize) >= pg.Total {
			return res, nil
		}
	}
}
