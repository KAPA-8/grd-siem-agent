package collector

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/grd-platform/grd-siem-agent/internal/config"
)

// Factory creates a Collector from the SIEM and sync configuration.
type Factory func(cfg config.SIEMConfig, syncCfg config.SyncConfig) (Collector, error)

// Validator checks the type-specific part of the SIEM configuration. It runs
// during config.Load, before any collector is built. It may be nil.
type Validator func(cfg config.SIEMConfig) error

type registration struct {
	factory  Factory
	validate Validator
}

var (
	mu       sync.RWMutex
	registry = map[string]registration{}
)

// The registry is the single source of truth for supported SIEM types:
// config.Load validates siem.type (and the type-specific settings) through it.
func init() {
	config.SetSIEMValidator(ValidateConfig)
}

// Register adds a collector to the registry. It is called from init()
// functions in each collector package, which main imports for side effects.
// Registering the same name twice panics, as that is a programming error.
func Register(name string, factory Factory, validate Validator) {
	if name == "" || factory == nil {
		panic("collector: Register requires a name and a factory")
	}
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[name]; dup {
		panic(fmt.Sprintf("collector: %q registered twice", name))
	}
	registry[name] = registration{factory: factory, validate: validate}
}

// Registered returns the registered SIEM types, sorted.
func Registered() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ValidateConfig checks that cfg.Type is a registered SIEM type and runs the
// type-specific validator.
func ValidateConfig(cfg config.SIEMConfig) error {
	mu.RLock()
	reg, ok := registry[cfg.Type]
	mu.RUnlock()
	if !ok {
		return unknownTypeError(cfg.Type)
	}
	if reg.validate == nil {
		return nil
	}
	return reg.validate(cfg)
}

// New creates a new Collector for the given SIEM type.
// Returns an error if the type is not registered or the factory fails.
func New(cfg config.SIEMConfig, syncCfg config.SyncConfig) (Collector, error) {
	mu.RLock()
	reg, ok := registry[cfg.Type]
	mu.RUnlock()
	if !ok {
		return nil, unknownTypeError(cfg.Type)
	}
	return reg.factory(cfg, syncCfg)
}

func unknownTypeError(siemType string) error {
	return fmt.Errorf("siem.type %q is not supported (available: %s)", siemType, strings.Join(Registered(), ", "))
}
