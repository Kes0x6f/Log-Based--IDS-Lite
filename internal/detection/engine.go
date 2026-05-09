package detection

import (
	"log"
	"math"
	"strconv"
	"sync"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/database"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// globalSensitivity holds the three global tuning values read from the
// settings table. ThresholdMul of 1.0 means no change. Nil WindowSec or
// CooldownSec means "use each rule's compiled default."
type globalSensitivity struct {
	ThresholdMul float64 // 0.5 = more sensitive, 2.0 = less sensitive
	WindowSec    *int    // nil = no global override
	CooldownSec  *int    // nil = no global override
}

// ruleState is a point-in-time snapshot of all config data needed for one
// event cycle. Produced by loadCache(), consumed by resolve().
// Passing it as a value means every event sees a consistent view of config
// even if another goroutine invalidates the cache mid-flight.
type ruleState struct {
	overrides map[string]database.RuleConfig
	global    globalSensitivity
}

var defaultState = ruleState{global: globalSensitivity{ThresholdMul: 1.0}}

type Engine struct {
	Registry    *RuleRegistry
	State       *context.DetectionContext
	ConfigStore *database.RuleConfigRepository
	Settings    *database.SettingsRepository // nil = no global sensitivity

	// ── Config cache ──────────────────────────────────────────────────────────
	cacheMu         sync.RWMutex
	cachedOverrides map[string]database.RuleConfig
	cachedGlobal    globalSensitivity
	cacheLoadedAt   time.Time
	cacheTTL        time.Duration
}

// NewEngine constructs an Engine. Pass nil for configStore and settings to
// run with all compiled defaults (useful in tests).
func NewEngine(rules []Rule, configStore *database.RuleConfigRepository, settings *database.SettingsRepository) *Engine {
	return &Engine{
		Registry:    NewRuleRegistry(rules),
		State:       context.NewDetectionContext(),
		ConfigStore: configStore,
		Settings:    settings,
		cacheTTL:    10 * time.Second,
	}
}

// loadCache returns a ruleState snapshot, refreshing both the per-rule
// overrides and the global sensitivity settings when the TTL has elapsed.
// Uses a double-checked lock so concurrent goroutines never race on a DB read.
func (e *Engine) loadCache() (ruleState, error) {
	// ── Fast path ─────────────────────────────────────────────────────────────
	e.cacheMu.RLock()
	if e.cachedOverrides != nil && time.Since(e.cacheLoadedAt) < e.cacheTTL {
		s := ruleState{overrides: e.cachedOverrides, global: e.cachedGlobal}
		e.cacheMu.RUnlock()
		return s, nil
	}
	e.cacheMu.RUnlock()

	// ── Slow path: reload ─────────────────────────────────────────────────────
	e.cacheMu.Lock()
	defer e.cacheMu.Unlock()

	// Another goroutine may have refreshed while we waited for the write lock.
	if e.cachedOverrides != nil && time.Since(e.cacheLoadedAt) < e.cacheTTL {
		return ruleState{overrides: e.cachedOverrides, global: e.cachedGlobal}, nil
	}

	// ── Load per-rule overrides ───────────────────────────────────────────────
	var overrides map[string]database.RuleConfig
	if e.ConfigStore != nil {
		var err error
		overrides, err = e.ConfigStore.GetAll()
		if err != nil {
			if e.cachedOverrides != nil {
				log.Println("Engine: override refresh failed, serving stale cache:", err)
				return ruleState{overrides: e.cachedOverrides, global: e.cachedGlobal}, nil
			}
			return ruleState{}, err
		}
	}

	// ── Load global sensitivity ───────────────────────────────────────────────
	// Keys: "global-threshold-mul", "global-window-sec", "global-cooldown-sec"
	// All stored as strings in the settings table.
	global := globalSensitivity{ThresholdMul: 1.0}
	if e.Settings != nil {
		all, err := e.Settings.GetAll()
		if err == nil {
			if mul := all["global-threshold-mul"]; mul != "" && mul != "1" {
				if f, err2 := strconv.ParseFloat(mul, 64); err2 == nil && f > 0 {
					global.ThresholdMul = f
				}
			}
			if ws := all["global-window-sec"]; ws != "" {
				if n, err2 := strconv.Atoi(ws); err2 == nil && n > 0 {
					global.WindowSec = &n
				}
			}
			if cs := all["global-cooldown-sec"]; cs != "" {
				if n, err2 := strconv.Atoi(cs); err2 == nil && n >= 0 {
					global.CooldownSec = &n
				}
			}
		}
	}

	log.Printf("Engine: config cache refreshed (%d rule override(s), threshold-mul=%.2fx)",
		len(overrides), global.ThresholdMul)

	e.cachedOverrides = overrides
	e.cachedGlobal = global
	e.cacheLoadedAt = time.Now()

	return ruleState{overrides: overrides, global: global}, nil
}

// InvalidateCache forces the next loadCache() call to re-read the DB,
// bypassing the TTL. Call this after any write to rule_config or to the
// global sensitivity settings keys.
func (e *Engine) InvalidateCache() {
	e.cacheMu.Lock()
	e.cacheLoadedAt = time.Time{}
	e.cacheMu.Unlock()
}

// resolve merges config in three priority layers:
//
//  1. Compiled defaults (lowest)
//  2. Global sensitivity overrides
//  3. Per-rule DB overrides (highest)
//
// Per-rule always wins. Global sensitivity only applies where no per-rule
// override exists for that specific field.
func (e *Engine) resolve(meta RuleMeta, state ruleState) ResolvedConfig {
	// Layer 1: compiled defaults
	threshold := meta.Defaults.Threshold
	windowSec := meta.Defaults.WindowSec
	cooldownSec := meta.Defaults.CooldownSec
	enabled := true

	// Layer 2: global sensitivity
	g := state.global
	if g.ThresholdMul != 0 && g.ThresholdMul != 1.0 && threshold > 0 {
		v := int(math.Round(float64(threshold) * g.ThresholdMul))
		if v < 1 {
			v = 1 // threshold can never go below 1
		}
		threshold = v
	}
	if g.WindowSec != nil {
		windowSec = *g.WindowSec
	}
	if g.CooldownSec != nil {
		cooldownSec = *g.CooldownSec
	}

	// Layer 3: per-rule DB override
	if meta.DisplayName != "" && state.overrides != nil {
		if override, ok := state.overrides[meta.DisplayName]; ok {
			enabled = override.Enabled
			if override.Threshold != nil {
				threshold = *override.Threshold
			}
			if override.WindowSec != nil {
				windowSec = *override.WindowSec
			}
			if override.CooldownSec != nil {
				cooldownSec = *override.CooldownSec
			}
		}
	}

	return ResolvedConfig{
		Threshold: threshold,
		Window:    time.Duration(windowSec) * time.Second,
		Cooldown:  time.Duration(cooldownSec) * time.Second,
		Enabled:   enabled,
	}
}

// Resolve is the public, cache-backed resolver for API handlers.
func (e *Engine) Resolve(meta RuleMeta) ResolvedConfig {
	if e.ConfigStore == nil {
		return e.resolve(meta, defaultState)
	}
	state, err := e.loadCache()
	if err != nil {
		log.Println("Engine.Resolve: config load failed:", err)
		return e.resolve(meta, defaultState)
	}
	return e.resolve(meta, state)
}

// DescribeAll returns the RuleMeta for every registered rule, deduplicated.
func (e *Engine) DescribeAll() []RuleMeta {
	rules := e.Registry.AllRules()
	metas := make([]RuleMeta, 0, len(rules))
	for _, r := range rules {
		metas = append(metas, r.Meta())
	}
	return metas
}

func (e *Engine) Process(input <-chan *model.NormalizedEvent, output chan<- *model.Alert) {
	for event := range input {
		state := defaultState
		if e.ConfigStore != nil {
			var err error
			state, err = e.loadCache()
			if err != nil {
				log.Println("Engine.Process: config load failed:", err)
				state = defaultState
			}
		}

		rules := e.Registry.GetRules(event)
		for _, rule := range rules {
			cfg := e.resolve(rule.Meta(), state)
			if !cfg.Enabled {
				continue
			}
			for _, alert := range rule.Evaluate(event, e.State, cfg) {
				output <- alert
			}
		}
	}
}
