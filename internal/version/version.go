package version

// Build-time variables injected via -ldflags.
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)
