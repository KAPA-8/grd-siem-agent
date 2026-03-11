package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/mod/semver"

	"github.com/grd-platform/grd-siem-agent/internal/config"
	"github.com/grd-platform/grd-siem-agent/internal/version"
)

// ExitCodeUpdate is the exit code used to signal that the agent
// should restart to apply a pending update.
const ExitCodeUpdate = 2

// Updater checks for and applies agent updates from GitHub Releases.
type Updater struct {
	cfg        config.UpdateConfig
	httpClient *http.Client
	stagingDir string
}

// ReleaseInfo holds metadata about a GitHub release.
type ReleaseInfo struct {
	TagName     string         `json:"tag_name"`
	Prerelease  bool           `json:"prerelease"`
	Draft       bool           `json:"draft"`
	Assets      []ReleaseAsset `json:"assets"`
	PublishedAt string         `json:"published_at"`
}

// ReleaseAsset is a single file attached to a GitHub release.
type ReleaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// PendingUpdate is the marker written to disk when an update is staged.
type PendingUpdate struct {
	Version        string `json:"version"`
	SHA256         string `json:"sha256"`
	BinaryPath     string `json:"binary_path"`
	DownloadedAt   string `json:"downloaded_at"`
	CurrentVersion string `json:"current_version"`
}

// CheckResult is the outcome of a version check.
type CheckResult struct {
	CurrentVersion  string
	LatestVersion   string
	UpdateAvailable bool
}

// New creates a new Updater.
func New(cfg config.UpdateConfig) *Updater {
	stagingDir := "/var/lib/grd-siem-agent/.update"
	if runtime.GOOS == "windows" {
		stagingDir = filepath.Join(os.Getenv("ProgramData"), "GRD SIEM Agent", "update")
	}

	return &Updater{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
		},
		stagingDir: stagingDir,
	}
}

// Run starts the periodic update check loop. Blocks until context is cancelled.
func (u *Updater) Run(ctx context.Context) {
	if !u.cfg.Enabled {
		log.Info().Msg("auto-update disabled")
		return
	}

	interval := time.Duration(u.cfg.CheckIntervalHours) * time.Hour
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	log.Info().
		Dur("interval", interval).
		Str("repo", u.cfg.GitHubRepo).
		Msg("update checker started")

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("update checker stopped")
			return
		case <-ticker.C:
			u.checkAndStage(ctx)
		}
	}
}

// Check queries GitHub for the latest release and compares versions.
func (u *Updater) Check(ctx context.Context) (*CheckResult, error) {
	release, err := u.fetchLatestRelease(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching latest release: %w", err)
	}

	current := ensureVPrefix(version.Version)
	latest := ensureVPrefix(release.TagName)

	result := &CheckResult{
		CurrentVersion:  version.Version,
		LatestVersion:   release.TagName,
		UpdateAvailable: false,
	}

	if !semver.IsValid(current) {
		log.Warn().Str("version", version.Version).Msg("current version is not valid semver, cannot compare")
		return result, nil
	}

	if !semver.IsValid(latest) {
		log.Warn().Str("version", release.TagName).Msg("latest release is not valid semver, skipping")
		return result, nil
	}

	if semver.Compare(latest, current) > 0 {
		result.UpdateAvailable = true
	}

	return result, nil
}

// CheckAndApply checks for an update, downloads and stages it.
// Returns true if an update was staged and the caller should restart.
func (u *Updater) CheckAndApply(ctx context.Context) (bool, error) {
	result, err := u.Check(ctx)
	if err != nil {
		return false, err
	}

	if !result.UpdateAvailable {
		log.Info().
			Str("current", result.CurrentVersion).
			Str("latest", result.LatestVersion).
			Msg("agent is up to date")
		return false, nil
	}

	log.Info().
		Str("current", result.CurrentVersion).
		Str("latest", result.LatestVersion).
		Msg("update available, downloading")

	if err := u.downloadAndStage(ctx, result.LatestVersion); err != nil {
		return false, fmt.Errorf("staging update: %w", err)
	}

	return true, nil
}

// fetchLatestRelease queries the GitHub API for the latest release.
func (u *Updater) fetchLatestRelease(ctx context.Context) (*ReleaseInfo, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", u.cfg.GitHubRepo)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "grd-siem-agent/"+version.Version)

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github API request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("no releases found for %s", u.cfg.GitHubRepo)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("github API error (%d): %s", resp.StatusCode, string(body))
	}

	var release ReleaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("decoding release: %w", err)
	}

	if release.Draft {
		return nil, fmt.Errorf("latest release is a draft, skipping")
	}

	if release.Prerelease && !u.cfg.AllowPrerelease {
		return nil, fmt.Errorf("latest release is a prerelease and allow_prerelease is false")
	}

	return &release, nil
}

// downloadAndStage downloads the correct binary and checksums file,
// verifies integrity, and writes the pending update marker.
func (u *Updater) downloadAndStage(ctx context.Context, tagName string) error {
	if err := os.MkdirAll(u.stagingDir, 0o755); err != nil {
		return fmt.Errorf("creating staging dir: %w", err)
	}

	binaryName := BinaryAssetName()

	release, err := u.fetchLatestRelease(ctx)
	if err != nil {
		return err
	}

	var binaryAsset, checksumAsset *ReleaseAsset
	for i, a := range release.Assets {
		if a.Name == binaryName {
			binaryAsset = &release.Assets[i]
		}
		if a.Name == "checksums.txt" {
			checksumAsset = &release.Assets[i]
		}
	}

	if binaryAsset == nil {
		return fmt.Errorf("binary asset %q not found in release %s", binaryName, tagName)
	}
	if checksumAsset == nil {
		return fmt.Errorf("checksums.txt not found in release %s", tagName)
	}

	// Download checksums first (small file)
	checksumData, err := u.downloadToMemory(ctx, checksumAsset.BrowserDownloadURL)
	if err != nil {
		return fmt.Errorf("downloading checksums: %w", err)
	}

	expectedHash, err := ParseChecksum(string(checksumData), binaryName)
	if err != nil {
		return fmt.Errorf("parsing checksum: %w", err)
	}

	// Download binary to staging
	stagedPath := filepath.Join(u.stagingDir, "grd-siem-agent.new")
	actualHash, err := u.downloadToFile(ctx, binaryAsset.BrowserDownloadURL, stagedPath)
	if err != nil {
		os.Remove(stagedPath)
		return fmt.Errorf("downloading binary: %w", err)
	}

	if actualHash != expectedHash {
		os.Remove(stagedPath)
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedHash, actualHash)
	}

	log.Info().
		Str("version", tagName).
		Str("sha256", actualHash).
		Msg("update binary verified")

	if err := os.Chmod(stagedPath, 0o755); err != nil {
		return fmt.Errorf("chmod staged binary: %w", err)
	}

	// Write pending update marker
	pending := PendingUpdate{
		Version:        tagName,
		SHA256:         actualHash,
		BinaryPath:     stagedPath,
		DownloadedAt:   time.Now().UTC().Format(time.RFC3339),
		CurrentVersion: version.Version,
	}

	pendingData, err := json.MarshalIndent(pending, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling pending update: %w", err)
	}

	pendingPath := filepath.Join(u.stagingDir, "pending.json")
	if err := os.WriteFile(pendingPath, pendingData, 0o644); err != nil {
		return fmt.Errorf("writing pending marker: %w", err)
	}

	log.Info().
		Str("version", tagName).
		Str("staged_path", stagedPath).
		Msg("update staged, pending restart")

	return nil
}

// downloadToMemory fetches a URL and returns its entire body.
func (u *Updater) downloadToMemory(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "grd-siem-agent/"+version.Version)

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// downloadToFile downloads a URL to a file, returning the SHA256 hash.
func (u *Updater) downloadToFile(ctx context.Context, url, destPath string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "grd-siem-agent/"+version.Version)

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	f, err := os.Create(destPath)
	if err != nil {
		return "", fmt.Errorf("creating file: %w", err)
	}
	defer f.Close()

	hasher := sha256.New()
	writer := io.MultiWriter(f, hasher)

	if _, err := io.Copy(writer, resp.Body); err != nil {
		return "", fmt.Errorf("writing file: %w", err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// checkAndStage is the periodic check called from Run().
func (u *Updater) checkAndStage(ctx context.Context) {
	result, err := u.Check(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("update check failed")
		return
	}

	if !result.UpdateAvailable {
		log.Debug().
			Str("current", result.CurrentVersion).
			Str("latest", result.LatestVersion).
			Msg("no update available")
		return
	}

	log.Info().
		Str("current", result.CurrentVersion).
		Str("latest", result.LatestVersion).
		Msg("update available, staging download")

	if err := u.downloadAndStage(ctx, result.LatestVersion); err != nil {
		log.Error().Err(err).Msg("failed to stage update")
		return
	}

	// Signal for restart — the ExecStartPre script will apply the update
	log.Info().Msg("update staged, exiting for service restart to apply update")
	os.Exit(ExitCodeUpdate)
}

// BinaryAssetName returns the expected GitHub Release asset name
// for the current OS and architecture.
func BinaryAssetName() string {
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	return fmt.Sprintf("grd-siem-agent-%s-%s%s", runtime.GOOS, runtime.GOARCH, ext)
}

// ParseChecksum extracts the SHA256 hash for a given filename from
// a checksums file (one "hash  filename" per line).
func ParseChecksum(checksumData, filename string) (string, error) {
	for _, line := range strings.Split(checksumData, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 && parts[1] == filename {
			return parts[0], nil
		}
	}
	return "", fmt.Errorf("checksum not found for %s", filename)
}

// EnsureVPrefix ensures a version string has the "v" prefix
// required by golang.org/x/mod/semver.
func EnsureVPrefix(v string) string {
	if !strings.HasPrefix(v, "v") {
		return "v" + v
	}
	return v
}

// ensureVPrefix is the internal version used by the package.
func ensureVPrefix(v string) string {
	return EnsureVPrefix(v)
}
