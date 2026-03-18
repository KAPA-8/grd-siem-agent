package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/kardianos/service"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/grd-platform/grd-siem-agent/internal/agent"
	"github.com/grd-platform/grd-siem-agent/internal/config"
	"github.com/grd-platform/grd-siem-agent/internal/logging"
	"github.com/grd-platform/grd-siem-agent/internal/updater"
	"github.com/grd-platform/grd-siem-agent/internal/version"

	// Register collectors via init()
	_ "github.com/grd-platform/grd-siem-agent/internal/collector/qradar"
)

var configPath string

func main() {
	rootCmd := &cobra.Command{
		Use:   "grd-siem-agent",
		Short: "GRD SIEM Agent - On-premises collector for SIEM integration",
		Long:  "Collects alerts from SIEMs (QRadar, Splunk, Sentinel) and sends them to the GRD platform.",
	}

	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "config.yaml", "path to config file")

	rootCmd.AddCommand(runCmd())
	rootCmd.AddCommand(validateCmd())
	rootCmd.AddCommand(versionCmd())
	rootCmd.AddCommand(updateCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// agentService wraps the Agent to implement kardianos/service.Interface
type agentService struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func (s *agentService) Start(svc service.Service) error {
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

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Error().Err(err).Msg("failed to load config")
		return
	}

	if err := logging.Setup(cfg.Logging.Level, cfg.Logging.Path); err != nil {
		log.Error().Err(err).Msg("failed to setup logging")
		return
	}

	log.Info().
		Str("config", configPath).
		Str("version", version.Version).
		Msg("GRD SIEM Agent starting (service mode)")

	a, err := agent.New(cfg, configPath)
	if err != nil {
		log.Error().Err(err).Msg("failed to create agent")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	if err := a.Run(ctx); err != nil {
		log.Error().Err(err).Msg("agent stopped with error")
	}
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

			svc := &agentService{}
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
		Msg("GRD SIEM Agent starting")

	a, err := agent.New(cfg, configPath)
	if err != nil {
		return fmt.Errorf("creating agent: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	return a.Run(ctx)
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

			fmt.Printf("Config is valid.\n")
			fmt.Printf("  Agent ID:      %s\n", cfg.Agent.ID)
			fmt.Printf("  Agent Name:    %s\n", cfg.Agent.Name)
			fmt.Printf("  SIEM Type:     %s\n", cfg.SIEM.Type)
			fmt.Printf("  SIEM URL:      %s\n", cfg.SIEM.APIURL)
			fmt.Printf("  Connection ID: %s\n", cfg.SIEM.ConnectionID)
			fmt.Printf("  Platform:      %s\n", cfg.Platform.URL)
			fmt.Printf("  Interval:      %d minutes\n", cfg.Sync.IntervalMinutes)
			fmt.Printf("  Lookback:      %d days\n", cfg.Sync.LookbackDays)
			fmt.Printf("  Buffer:        %v (%s)\n", cfg.Buffer.Enabled, cfg.Buffer.Path)

			return nil
		},
	}
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
