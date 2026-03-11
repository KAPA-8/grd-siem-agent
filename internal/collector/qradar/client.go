package qradar

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	defaultPageSize = 50
	httpTimeout     = 30 * time.Second
)

// Client is the HTTP client for the QRadar REST API.
type Client struct {
	baseURL    string
	apiKey     string
	apiVersion string
	httpClient *http.Client
}

// NewClient creates a new QRadar API client.
// apiVersion should be a QRadar API version (e.g., "19.0", "20.0", "26.0").
// If empty, defaults to "19.0" (compatible with QRadar 7.5.0 UP3+).
func NewClient(baseURL, apiKey string, validateSSL bool, apiVersion string) *Client {
	transport := &http.Transport{}
	if !validateSSL {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // User explicitly disabled SSL validation
		}
	}

	if apiVersion == "" {
		apiVersion = "19.0"
	}

	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		apiKey:     apiKey,
		apiVersion: apiVersion,
		httpClient: &http.Client{
			Timeout:   httpTimeout,
			Transport: transport,
		},
	}
}

// GetSystemInfo calls GET /api/system/about to verify connectivity and get version.
func (c *Client) GetSystemInfo(ctx context.Context) (*QRadarSystemInfo, error) {
	body, err := c.doRequest(ctx, "GET", "/api/system/about", nil, "")
	if err != nil {
		return nil, fmt.Errorf("system info: %w", err)
	}
	defer body.Close()

	var info QRadarSystemInfo
	if err := json.NewDecoder(body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decoding system info: %w", err)
	}
	return &info, nil
}

// GetOffenses fetches offenses with optional filter, sorted by last_updated_time ASC.
// Uses Range header for pagination. Returns all matching offenses up to maxResults.
func (c *Client) GetOffenses(ctx context.Context, filter string, maxResults int) ([]QRadarOffense, error) {
	var allOffenses []QRadarOffense
	offset := 0

	for {
		if maxResults > 0 && len(allOffenses) >= maxResults {
			break
		}

		pageSize := defaultPageSize
		remaining := maxResults - len(allOffenses)
		if maxResults > 0 && remaining < pageSize {
			pageSize = remaining
		}

		rangeHeader := fmt.Sprintf("items=%d-%d", offset, offset+pageSize-1)

		params := url.Values{}
		if filter != "" {
			params.Set("filter", filter)
		}
		params.Set("sort", "+last_updated_time")

		path := "/api/siem/offenses"
		if len(params) > 0 {
			path += "?" + params.Encode()
		}

		body, err := c.doRequest(ctx, "GET", path, nil, rangeHeader)
		if err != nil {
			return allOffenses, fmt.Errorf("fetching offenses (offset=%d): %w", offset, err)
		}

		var page []QRadarOffense
		if err := json.NewDecoder(body).Decode(&page); err != nil {
			body.Close()
			return allOffenses, fmt.Errorf("decoding offenses: %w", err)
		}
		body.Close()

		allOffenses = append(allOffenses, page...)

		log.Debug().
			Int("page_size", len(page)).
			Int("total", len(allOffenses)).
			Int("offset", offset).
			Msg("fetched offenses page")

		// If we got fewer than requested, we've reached the end
		if len(page) < pageSize {
			break
		}

		offset += pageSize
	}

	return allOffenses, nil
}

// GetOffenseNotes fetches notes for a specific offense.
func (c *Client) GetOffenseNotes(ctx context.Context, offenseID int64) ([]QRadarNote, error) {
	path := fmt.Sprintf("/api/siem/offenses/%d/notes", offenseID)

	body, err := c.doRequest(ctx, "GET", path, nil, "")
	if err != nil {
		return nil, fmt.Errorf("fetching notes for offense %d: %w", offenseID, err)
	}
	defer body.Close()

	var notes []QRadarNote
	if err := json.NewDecoder(body).Decode(&notes); err != nil {
		return nil, fmt.Errorf("decoding notes: %w", err)
	}
	return notes, nil
}

// doRequest executes an HTTP request against the QRadar API.
func (c *Client) doRequest(ctx context.Context, method, path string, reqBody io.Reader, rangeHeader string) (io.ReadCloser, error) {
	fullURL := c.baseURL + path

	req, err := http.NewRequestWithContext(ctx, method, fullURL, reqBody)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// QRadar uses SEC header for authentication
	req.Header.Set("SEC", c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Version", c.apiVersion)

	if rangeHeader != "" {
		req.Header.Set("Range", rangeHeader)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request %s %s: %w", method, path, err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		return nil, fmt.Errorf("authentication failed (401): check your QRadar API key")
	}

	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return resp.Body, nil
}
