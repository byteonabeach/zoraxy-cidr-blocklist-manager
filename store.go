package main

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

type sourceState struct {
	Config        sourceConfig
	LoadedEntries int
	UniqueEntries int
	LastRefresh   time.Time
	LastError     string
	Hits          atomic.Int64
	set           *ipSet
}

type store struct {
	sources     map[string]*sourceState
	uniqueCount int
	lastBuild   time.Time
}

type sourceSummary struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	URL           string    `json:"url"`
	Enabled       bool      `json:"enabled"`
	LoadedEntries int       `json:"loaded_entries"`
	UniqueEntries int       `json:"unique_entries"`
	LastRefresh   time.Time `json:"last_refresh"`
	LastError     string    `json:"last_error,omitempty"`
	Hits          int64     `json:"hits"`
	SupportsIPv4  bool      `json:"supports_ipv4"`
	SupportsIPv6  bool      `json:"supports_ipv6"`
}

type statusResponse struct {
	Loaded        bool            `json:"loaded"`
	SourceCount   int             `json:"source_count"`
	EnabledCount  int             `json:"enabled_count"`
	DisabledCount int             `json:"disabled_count"`
	UniqueEntries int             `json:"unique_entries"`
	BlockedCount  int64           `json:"blocked_count"`
	LastRefresh   time.Time       `json:"last_refresh"`
	Sources       []sourceSummary `json:"sources"`
	Refreshing    bool            `json:"refreshing"`
}

var (
	stateMu      sync.RWMutex
	current      *store
	refreshing   atomic.Int32
	blockedCount atomic.Int64
)

func snapshotStore() *store {
	stateMu.RLock()
	defer stateMu.RUnlock()
	return current
}

func buildStoreFromSources(sources map[string]*sourceState) *store {
	if sources == nil {
		sources = map[string]*sourceState{}
	}
	next := &store{
		sources:   sources,
		lastBuild: time.Now(),
	}
	count := 0
	for _, src := range sources {
		if src != nil && src.Config.Enabled {
			count += src.UniqueEntries
		}
	}
	next.uniqueCount = count
	return next
}

func cloneSourceMap(src map[string]*sourceState) map[string]*sourceState {
	out := make(map[string]*sourceState, len(src))
	for id, s := range src {
		if s != nil {
			out[id] = s.clone()
		}
	}
	return out
}

func syncStoreWithConfig() {
	cfg := snapshotConfig()
	old := snapshotStore()
	newSources := make(map[string]*sourceState, len(cfg.Sources))
	for _, sc := range cfg.Sources {
		if prev, ok := old.sources[sc.ID]; ok && prev != nil {
			clone := prev.clone()
			clone.Config = sc
			newSources[sc.ID] = clone
		} else {
			newSources[sc.ID] = &sourceState{Config: sc}
		}
	}
	next := buildStoreFromSources(newSources)
	stateMu.Lock()
	current = next
	stateMu.Unlock()
}

func (s *store) matches(addr netip.Addr) (bool, []string) {
	if s == nil {
		return false, nil
	}
	var matched []string
	for id, src := range s.sources {
		if src == nil || !src.Config.Enabled {
			continue
		}
		if src.set != nil && src.set.Contains(addr) {
			matched = append(matched, id)
		}
	}
	return len(matched) > 0, matched
}

func (s *sourceState) clone() *sourceState {
	if s == nil {
		return nil
	}
	out := &sourceState{
		Config:        s.Config,
		LoadedEntries: s.LoadedEntries,
		UniqueEntries: s.UniqueEntries,
		LastRefresh:   s.LastRefresh,
		LastError:     s.LastError,
		set:           s.set,
	}
	out.Hits.Store(s.Hits.Load())
	return out
}
