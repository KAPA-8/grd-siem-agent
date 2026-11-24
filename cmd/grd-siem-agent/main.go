package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kardianos/service"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/grd-platform/grd-siem-agent/internal/agent"
	"github.com/grd-platform/grd-siem-agent/internal/collector"
	"github.com/grd-platform/grd-siem-agent/internal/config"
	"github.com/grd-platform/grd-siem-agent/internal/logging"
	"github.com/grd-platform/grd-siem-agent/internal/updater"
	"github.com/grd-platform/grd-siem-agent/internal/version"

	// Register collectors via init()
	_ "github.com/grd-platform/grd-siem-agent/internal/collector/fortisiem"
	_ "github.com/grd-platform/grd-siem-agent/internal/collector/qradar"
	_ "github.com/grd-platform/grd-siem-agent/internal/collector/stellarcyber"
)

var configPath string

func main() {
	rootCmd := &cobra.Command{
		Use:   "grd-siem-agent",
		Short: "GRD SIEM Agent - On-premises collector for SIEM integration",
		Long:  "Collects alerts from SIEMs (IBM QRadar, Stellar Cyber Open XDR, FortiSIEM) and sends them to the GRD platform.",
	}

	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "config.yaml", "path to config file")

	rootCmd.AddCommand(runCmd())
	rootCmd.AddCommand(validateCmd())
	rootCmd.AddCommand(testSIEMCmd())
	rootCmd.AddCommand(versionCmd())
	rootCmd.AddCommand(updateCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// agentService wraps the Agent to implement kardianos/service.Interface.
//
// Under systemd or the Windows SCM, kardianos keeps the process alive until
// the service manager stops it, even after the agent goroutine returned. A
// fatal error (bad config, agent setup) must therefore end the process with a
// non-zero code so Restart=on-failure / SCM recovery restarts it, instead of
// leaving a "running" service that does nothing.
type agentService struct {
	run  func(ctx context.Context) error // the agent; runService by default
	exit func(code int)                  // os.Exit; replaced in tests

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

func newAgentService() *agentService {
	return &agentService{run: runService, exit: os.Exit}
}

func (s *agentService) Start(svc service.Service) error {
	// Created before the goroutine starts, so Stop never races with it.
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.done = make(chan struct{})
	go s.runAgent()
	return nil
}

func (s *agentService) Stop(svc service.Service) error {
	if s.cancel != nil {
		s.cancel()
	}
	if s.done != nil {
		<-s.done
	}
	return nil
}

func (s *agentService) runAgent() {
	defer close(s.done)

	err := s.run(s.ctx)
	if s.ctx.Err() != nil {
		return // stopped by the service manager
	}
	if err == nil {
		err = fmt.Errorf("agent stopped unexpectedly")
	}
	log.Error().Err(err).Msg("agent failed; exiting so the service manager restarts it")
	s.exit(1)
}

// runService runs the agent under the service manager.
func runService(ctx context.Context) error {
	return startAgent(ctx, "service")
}

// startAgent loads the configuration and runs the agent until ctx is done.
func startAgent(ctx context.Context, mode string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	if err := logging.Setup(cfg.Logging.Level, cfg.Logging.Path); err != nil {
		return fmt.Errorf("setting up logging: %w", err)
	}

	log.Info().
		Str("config", configPath).
		Str("version", version.Version).
		Str("mode", mode).
		Msg("GRD SIEM Agent starting")

	a, err := agent.New(cfg, configPath)
	if err != nil {
		return fmt.Errorf("creating agent: %w", err)
	}

	return a.Run(ctx)
}

func runCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Start the agent",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Detect if running as a Windows Service (or systemd, launchd, etc.)
			svcConfig := &service.Config{
				Name:        "GRDSIEMAgent",
				DisplayName: "GRD SIEM Agent",
				Description: "On-premises SIEM collector for GRD platform",
			}

			svc := newAgentService()
			s, err := service.New(svc, svcConfig)
			if err != nil {
				return fmt.Errorf("creating service wrapper: %w", err)
			}

			// If running interactively (console), use signal handling
			if service.Interactive() {
				return runInteractive()
			}

			// Running as a system service — let kardianos handle the lifecycle
			return s.Run()
		},
	}
}

// runInteractive runs the agent in foreground/console mode with signal handling.
func runInteractive() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return startAgent(ctx, "console")
}

func validateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Validate the configuration file",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("config validation failed: %w", err)
			}
			// Building the collector also checks files it needs (ca_cert_file).
			coll, err := collector.New(cfg.SIEM, cfg.Sync)
			if err != nil {
				return fmt.Errorf("config validation failed: %w", err)
			}
			_ = coll.Close()

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Config is valid.\n")
			fmt.Fprintf(out, "  Agent ID:      %s\n", cfg.Agent.ID)
			fmt.Fprintf(out, "  Agent Name:    %s\n", cfg.Agent.Name)
			fmt.Fprintf(out, "  SIEM Type:     %s\n", cfg.SIEM.Type)
			fmt.Fprintf(out, "  SIEM URL:      %s\n", cfg.SIEM.APIURL)
			if cfg.SIEM.Type == "stellar_cyber" {
				fmt.Fprintf(out, "  Deployment:    %s\n", orDefault(cfg.SIEM.Deployment, "saas"))
				fmt.Fprintf(out, "  Data source:   %s\n", orDefault(cfg.SIEM.DataSource, "alerts"))
				fmt.Fprintf(out, "  Auth mode:     %s\n", orDefault(cfg.SIEM.Credentials.AuthMode, "api_token"))
				fmt.Fprintf(out, "  Tenant:        %s\n", orDefault(cfg.SIEM.Credentials.TenantID, "(all)"))
			}
			if cfg.SIEM.Type == "fortisiem" {
				cred := cfg.SIEM.Credentials
				authMode := orDefault(cred.AuthMode, "basic")
				fmt.Fprintf(out, "  Deployment:    %s\n", orDefault(cfg.SIEM.Deployment, "cloud"))
				fmt.Fprintf(out, "  Auth mode:     %s\n", authMode)
				if authMode == "basic" {
					user := cred.Username
					if !strings.Contains(user, "/") {
						user = orDefault(cred.Organization, "super") + "/" + user
					}
					fmt.Fprintf(out, "  User:          %s\n", user)
				}
				fmt.Fprintf(out, "  Tenant:        %s\n", orDefault(cred.TenantID, "(all)"))
				fmt.Fprintf(out, "  Security only: %v\n", cred.SecurityOnly)
				fmt.Fprintf(out, "  Status sweep:  %s\n", statusSweep(cfg.Sync.StatusRefreshHours))
			}
			fmt.Fprintf(out, "  Connection ID: %s\n", cfg.SIEM.ConnectionID)
			fmt.Fprintf(out, "  Platform:      %s\n", cfg.Platform.URL)
			fmt.Fprintf(out, "  Interval:      %d minutes\n", cfg.Sync.IntervalMinutes)
			fmt.Fprintf(out, "  Lookback:      %d days\n", cfg.Sync.LookbackDays)
			fmt.Fprintf(out, "  Max alerts:    %d per cycle\n", cfg.Sync.MaxAlertsPerSync)
			fmt.Fprintf(out, "  Buffer:        %v (%s)\n", cfg.Buffer.Enabled, cfg.Buffer.Path)
			fmt.Fprintf(out, "  Checkpoint:    %s\n", config.CheckpointPath(cfg))

			return nil
		},
	}
}

func statusSweep(hours int) string {
	if hours <= 0 {
		return "disabled"
	}
	return fmt.Sprintf("every %d hours", hours)
}

// testSIEMCmd checks the SIEM side of the configuration on site, before the
// agent is registered in GRD: it needs neither platform.agent_token nor
// siem.connection_id, and it never contacts the platform.
func testSIEMCmd() *cobra.Command {
	var collect bool
	var output string
	cmd := &cobra.Command{
		Use:   "test-siem",
		Short: "Test the connection to the SIEM (nothing is sent to the GRD platform)",
		Long: `Authenticates against the SIEM and runs a minimal query, without contacting
the GRD platform. With --collect it also runs one collection over the lookback
window and prints a summary (no checkpoint is saved); --output writes the
collected alerts to a JSON file for inspection.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadMinimal(configPath)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			if err := logging.Setup(cfg.Logging.Level, ""); err != nil {
				return fmt.Errorf("setting up logging: %w", err)
			}
			if err := collector.ValidateConfig(cfg.SIEM); err != nil {
				return fmt.Errorf("SIEM configuration is invalid: %w", err)
			}
			coll, err := collector.New(cfg.SIEM, cfg.Sync)
			if err != nil {
				return fmt.Errorf("SIEM configuration is invalid: %w", err)
			}
			defer coll.Close()

			parent := cmd.Context()
			if parent == nil {
				parent = context.Background()
			}
			ctx, stop := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			out := cmd.OutOrStdout()

			testCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			if tester, ok := coll.(collector.ConnectionTester); ok {
				msg, err := tester.TestConnection(testCtx)
				if err != nil {
					return fmt.Errorf("SIEM connection test failed: %w", err)
				}
				fmt.Fprintf(out, "SIEM connection OK: %s\n", msg)
			} else {
				if err := coll.Init(testCtx); err != nil {
					return fmt.Errorf("SIEM connection test failed: %w", err)
				}
				fmt.Fprintf(out, "SIEM connection OK (%s).\n", cfg.SIEM.Type)
			}
			if !collect {
				return nil
			}

			batch, err := coll.Collect(ctx, "")
			if err != nil {
				return fmt.Errorf("test collection failed: %w", err)
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
			fmt.Fprintf(out, "Test collection (nothing was sent to GRD, no checkpoint saved):\n")
			fmt.Fprintf(out, "  Window:        %s .. %s\n", batch.WindowFrom.UTC().Format(time.RFC3339), batch.WindowTo.UTC().Format(time.RFC3339))
			fmt.Fprintf(out, "  Read:          %d\n", batch.Fetched)
			fmt.Fprintf(out, "  Alerts:        %d (status only: %d, discarded at the source: %d)\n", len(batch.Templates), statusOnly, excluded)
			if output != "" {
				data, err := json.MarshalIndent(batch.Templates, "", "  ")
				if err != nil {
					return err
				}
				if err := os.WriteFile(output, data, 0o600); err != nil {
					return fmt.Errorf("writing %s: %w", output, err)
				}
				fmt.Fprintf(out, "  Written to:    %s\n", output)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&collect, "collect", false, "also run one collection over the lookback window and print a summary")
	cmd.Flags().StringVar(&output, "output", "", "with --collect, write the collected alerts to this JSON file")
	return cmd
}

func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("grd-siem-agent %s\n", version.Version)
			fmt.Printf("  commit: %s\n", version.Commit)
			fmt.Printf("  built:  %s\n", version.Date)
		},
	}
}

func updateCmd() *cobra.Command {
	var checkOnly bool

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Check for and apply agent updates",
		Long: `Checks GitHub Releases for a newer version of the agent.
Without flags, downloads and stages the update for the next service restart.
With --check, only reports whether an update is available.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadMinimal(configPath)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			upd := updater.New(cfg.Update)
			ctx := context.Background()

			if checkOnly {
				result, err := upd.Check(ctx)
				if err != nil {
					return fmt.Errorf("update check failed: %w", err)
				}

				fmt.Printf("Current version: %s\n", result.CurrentVersion)
				fmt.Printf("Latest version:  %s\n", result.LatestVersion)
				if result.UpdateAvailable {
					fmt.Printf("\nUpdate available! Run 'grd-siem-agent update' to apply.\n")
				} else {
					fmt.Printf("\nAgent is up to date.\n")
				}
				return nil
			}

			staged, err := upd.CheckAndApply(ctx)
			if err != nil {
				return fmt.Errorf("update failed: %w", err)
			}

			if !staged {
				fmt.Println("Agent is already up to date.")
				return nil
			}

			fmt.Println("Update downloaded and staged.")
			fmt.Println("Restart the service to apply: sudo systemctl restart grd-siem-agent")
			return nil
		},
	}

	cmd.Flags().BoolVar(&checkOnly, "check", false, "only check for updates, don't download")

	return cmd
}
