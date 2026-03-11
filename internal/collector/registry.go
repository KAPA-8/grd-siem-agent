package collector

import (
	"fmt"

	"github.com/grd-platform/grd-siem-agent/internal/config"
)

// Factory is a function that creates a new Collector from SIEM config.
type Factory func(cfg config.SIEMConfig, syncCfg config.SyncConfig) Collector

// registry holds registered collector factories keyed by SIEM type name.
var registry = map[string]Factory{}

// Register adds a collector factory to the registry.
// Called from init() functions in each collector package.
func Register(name string, factory Factory) {
	registry[name] = factory
}

// New creates a new Collector for the given SIEM type.
// Returns an error if the type is not registered.
func New(cfg config.SIEMConfig, syncCfg config.SyncConfig) (Collector, error) {
	factory, ok := registry[cfg.Type]
	if !ok {
		available := make([]string, 0, len(registry))
		for k := range registry {
			available = append(available, k)
		}
		return nil, fmt.Errorf("unknown SIEM type %q, available: %v", cfg.Type, available)
	}
	return factory(cfg, syncCfg), nil
}
