package fortisiem

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sort"
	"time"

	"github.com/rs/zerolog/log"
)

// Window partition (DESIGN §10).
//
// FortiSIEM's start/size paging is not stable: between two pages of the same
// query the server reorders incidents that share a sort key and shifts others
// across the page boundary, so a paged read of a window repeats some
// incidents and skips others (1-3 % measured on FortiSIEM Cloud, whatever
// the orderBy). A query that fits in ONE page is not affected. So a window is
// read with a single start=0 page when its total fits in pageSize; otherwise
// it is split into contiguous, non-overlapping subwindows of equal duration
// that are read in ascending order (recursively). Since incidentLastSeen only
// grows, an incident that moves while the window is being read lands in a
// later subwindow not read yet: it is never lost, and the repeats are
// deduplicated by incidentId. Only a window shorter than minSplitWindow that
// still holds more than pageSize incidents (many incidents last seen in the
// same second) is paged, by incidentId, and read again until the union holds
// total incidents or two reads in a row add none (at most four reads).
//
// Every window is delivered sorted by (incidentLastSeen, incidentId), so the
// output of a scan is ordered by incidentLastSeen whatever order the server
// applies: the checkpoint can stop at any incident, also when the server
// rejects orderBy incidentLastSeen.
const (
	// partitionFill sizes the subwindows to hold ~70 % of a page on average.
	partitionFill = 0.7
	// minSplitWindow is the shortest window that is still split. FortiSIEM
	// timestamps have second resolution, so shorter windows cannot be split
	// usefully.
	minSplitWindow = 2000 // ms
	// minSubwindow is the shortest subwindow a split produces.
	minSubwindow = 1000 // ms
	// orderByIncidentID sorts the paged read of a dense window.
	orderByIncidentID = "incidentId"
	// maxDensePasses bounds the reads of a dense window.
	maxDensePasses = 4
	// defaultMaxRequests bounds the incident queries of one collection.
	defaultMaxRequests = 2000
)

// errRequestLimit reports a collection that used up maxRequests queries.
var errRequestLimit = errors.New("fortisiem: se alcanzó el máximo de consultas a FortiSIEM en una sincronización")

// scannedIncident is one incident delivered by scanWindow.
type scannedIncident struct {
	raw         map[string]any
	id          string
	lastSeen    int64
	hasLastSeen bool
	// key is incidentLastSeen clamped to the window that returned it (the
	// end of that window when the incident has none): scans are ordered by it.
	key int64
}

// scanSink receives what scanWindow reads.
type scanSink struct {
	// incident receives the incidents in order; returning false stops the scan.
	incident func(scannedIncident) bool
	// invalid receives the number of data[] items without incidentId or
	// that are not objects.
	invalid func(n int)
}

// beginScan resets the per-collection query budget.
func (c *Collector) beginScan() { c.requests = 0 }

// scanWindow delivers every incident with incidentLastSeen in [from, to] to
// sink, ordered by incidentLastSeen. It reports whether sink stopped it.
func (c *Collector) scanWindow(ctx context.Context, from, to int64, sink *scanSink) (bool, error) {
	if from > to {
		return false, nil
	}
	pg, err := c.windowQuery(ctx, 0, c.pageSize, from, to, c.orderBy)
	if err != nil {
		return false, err
	}
	// The window is complete when the page brought as many distinct incidents
	// as its total (it may bring pageSize+1, §6.2). Without total (some
	// versions may omit it) a page shorter than pageSize is the whole window.
	distinct, invalid := pageIDs(pg.Data)
	complete := pg.Items < c.pageSize
	if pg.HasTotal {
		complete = int64(distinct+invalid+pg.Invalid) >= pg.Total
	}
	if complete {
		return deliver(pg.Data, pg.Invalid, from, to, sink), nil
	}
	if to-from < minSplitWindow {
		return c.scanDense(ctx, from, to, sink)
	}
	// Without total a full page means "maybe more": split as if it held four
	// pages, and every subwindow that comes back full again is split again.
	total := pg.Total
	if !pg.HasTotal {
		total = int64(4 * c.pageSize)
	}
	// A server that caps its pages below pageSize sets the real capacity.
	capacity := c.pageSize
	if pg.Items > 0 && pg.Items < c.pageSize {
		capacity = pg.Items
	}
	k := int64(math.Ceil(float64(total) / (partitionFill * float64(capacity))))
	span := to - from + 1
	k = max(min(k, span/minSubwindow), 2)
	for i := range k {
		a, b := from+span*i/k, from+span*(i+1)/k-1
		stopped, err := c.scanWindow(ctx, a, b, sink)
		if err != nil || stopped {
			return stopped, err
		}
	}
	return false, nil
}

// pageIDs counts the distinct incidentIds of a page and its items without one.
func pageIDs(data []map[string]any) (distinct, invalid int) {
	ids := make(map[string]struct{}, len(data))
	for _, inc := range data {
		id := incidentID(inc["incidentId"])
		if id == "" {
			invalid++
			continue
		}
		ids[id] = struct{}{}
	}
	return len(ids), invalid
}

// scanDense reads a window shorter than minSplitWindow that holds more than
// a page: it pages it by incidentId and reads it again, joining the reads,
// until the union holds total incidentIds or two reads in a row add none
// (at most maxDensePasses reads).
func (c *Collector) scanDense(ctx context.Context, from, to int64, sink *scanSink) (bool, error) {
	union := map[string]map[string]any{}
	invalid := 0
	complete := false
	passes, quiet := 0, 0
	var total int64
	for passes < maxDensePasses {
		passes++
		r, err := c.readDensePass(ctx, from, to, union)
		if err != nil {
			return false, err
		}
		if passes == 1 {
			invalid = r.invalid
		}
		if r.hasTotal {
			total = r.total
			if int64(len(union)+r.invalid) >= r.total {
				complete = true
				break
			}
		}
		if r.added == 0 {
			quiet++
		} else {
			quiet = 0
		}
		if quiet >= 2 {
			complete = !r.hasTotal
			break
		}
	}
	event := log.Warn()
	if complete {
		event = log.Info()
	}
	event.Time("from", time.UnixMilli(from).UTC()).Int("incidents", len(union)).Int64("total", total).Int("passes", passes).Bool("complete", complete).
		Msg("fortisiem: more than one page of incidents last seen within one second; read it page by page in several passes")
	items := make([]map[string]any, 0, len(union))
	for _, inc := range union {
		items = append(items, inc)
	}
	return deliver(items, invalid, from, to, sink), nil
}

// densePass is what one paged read of a dense window found.
type densePass struct {
	added, invalid int
	total          int64
	hasTotal       bool
}

// readDensePass pages [from, to] once, adding to union (the latest version of
// each incident wins). It reports the incidentIds it added to the union.
func (c *Collector) readDensePass(ctx context.Context, from, to int64, union map[string]map[string]any) (densePass, error) {
	var r densePass
	inPass := map[string]struct{}{}
	for page, start := 0, 0; page < c.maxPages; page, start = page+1, start+c.pageSize {
		pg, err := c.windowQuery(ctx, start, c.pageSize, from, to, c.denseOrderBy)
		if err != nil {
			return densePass{}, err
		}
		if pg.HasTotal {
			r.total, r.hasTotal = pg.Total, true
		}
		if pg.Items == 0 {
			break
		}
		r.invalid += pg.Invalid
		fresh := 0
		for _, inc := range pg.Data {
			id := incidentID(inc["incidentId"])
			if id == "" {
				r.invalid++
				continue
			}
			if _, ok := inPass[id]; !ok {
				inPass[id] = struct{}{}
				fresh++
			}
			if _, ok := union[id]; !ok {
				r.added++
			}
			union[id] = inc
		}
		if pg.HasTotal && int64(start+c.pageSize) >= pg.Total {
			break
		}
		// A page with no incident new to this read: the server ignores start.
		if fresh == 0 {
			break
		}
	}
	return r, nil
}

// windowQuery runs one incident query of a scan within the request budget.
// A server that rejects orderBy incidentId (HTTP 400) has its dense windows
// paged with the regular sort from then on.
func (c *Collector) windowQuery(ctx context.Context, start, size int, from, to int64, orderBy string) (*incidentPage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.requests >= c.maxRequests {
		return nil, fmt.Errorf("%w (%d); la ventana tiene demasiados incidentes: reduce sync.lookback_days", errRequestLimit, c.maxRequests)
	}
	c.requests++
	var (
		pg  *incidentPage
		err error
	)
	if orderBy == orderByIncidentID {
		pg, err = c.client.queryIncidents(ctx, newIncidentQuery(start, size, from, to, orderBy))
		var apiErr *APIError
		if err != nil && errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusBadRequest && apiErr.Path == incidentPath {
			log.Warn().Err(err).Msg("fortisiem: the server rejected orderBy incidentId; dense windows use the regular sort")
			c.denseOrderBy = c.orderBy
			pg, err = c.query(ctx, start, size, from, to)
		}
	} else {
		pg, err = c.query(ctx, start, size, from, to)
	}
	if err != nil {
		return nil, fmt.Errorf("consultando incidentes (start=%d): %w", start, err)
	}
	return pg, nil
}

// deliver sends the incidents of one window to sink sorted by
// (incidentLastSeen, incidentId). It reports whether sink stopped.
func deliver(data []map[string]any, invalid int, from, to int64, sink *scanSink) bool {
	items := make([]scannedIncident, 0, len(data))
	for _, inc := range data {
		id := incidentID(inc["incidentId"])
		if id == "" {
			invalid++
			continue
		}
		lastSeen, ok := epochMs(inc["incidentLastSeen"])
		key := to
		if ok {
			key = min(max(lastSeen, from), to)
		}
		items = append(items, scannedIncident{raw: inc, id: id, lastSeen: lastSeen, hasLastSeen: ok, key: key})
	}
	if invalid > 0 && sink.invalid != nil {
		sink.invalid(invalid)
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].key != items[j].key {
			return items[i].key < items[j].key
		}
		return lessID(items[i].id, items[j].id)
	})
	for _, it := range items {
		if !sink.incident(it) {
			return true
		}
	}
	return false
}

// lessID orders incidentIds numerically when both are integers.
func lessID(a, b string) bool {
	if len(a) != len(b) && isDigits(a) && isDigits(b) {
		return len(a) < len(b)
	}
	return a < b
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
