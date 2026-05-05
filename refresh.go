package main

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"
)

func refreshAllSources() error {
	if !refreshing.CompareAndSwap(0, 1) {
		return errors.New("refresh already in progress")
	}
	defer refreshing.Store(0)

	cfg := snapshotConfig()
	old := snapshotStore()
	newSources := make(map[string]*sourceState, len(cfg.Sources))
	var issues []string

	for _, sc := range cfg.Sources {
		sc.URL = normalizeSourceURL(sc.URL)
		prev := old.sources[sc.ID]
		base := &sourceState{Config: sc}
		if prev != nil {
			base.Hits.Store(prev.Hits.Load())
		}
		if !sc.Enabled {
			if prev != nil {
				clone := prev.clone()
				clone.Config = sc
				newSources[sc.ID] = clone
			} else {
				newSources[sc.ID] = base
			}
			continue
		}

		fetched, err := fetchSource(sc.URL)
		if err != nil {
			if prev != nil {
				clone := prev.clone()
				clone.Config = sc
				clone.LastError = err.Error()
				newSources[sc.ID] = clone
			} else {
				base.LastError = err.Error()
				newSources[sc.ID] = base
			}
			issues = append(issues, fmt.Sprintf("%s: %v", sc.Name, err))
			continue
		}

		base.LoadedEntries = fetched.loadedEntries
		base.UniqueEntries = fetched.uniqueEntries
		base.LastRefresh = time.Now()
		base.set = fetched.set
		newSources[sc.ID] = base
		runtime.GC()
	}

	next := buildStoreFromSources(newSources)
	stateMu.Lock()
	current = next
	stateMu.Unlock()
	runtime.GC()

	if len(issues) > 0 {
		return errors.New(strings.Join(issues, "; "))
	}
	return nil
}

func refreshOneSource(id string) error {
	if strings.TrimSpace(id) == "" {
		return refreshAllSources()
	}

	cfg := snapshotConfig()
	old := snapshotStore()
	var target *sourceConfig
	for _, s := range cfg.Sources {
		if s.ID == id {
			tmp := s
			tmp.URL = normalizeSourceURL(tmp.URL)
			target = &tmp
			break
		}
	}
	if target == nil {
		return fmt.Errorf("source %q not found in config", id)
	}

	newSources := cloneSourceMap(old.sources)
	if !target.Enabled {
		if existing, ok := newSources[id]; ok && existing != nil {
			clone := existing.clone()
			clone.Config = *target
			newSources[id] = clone
		} else {
			newSources[id] = &sourceState{Config: *target}
		}
		next := buildStoreFromSources(newSources)
		stateMu.Lock()
		current = next
		stateMu.Unlock()
		return nil
	}

	fetched, err := fetchSource(target.URL)
	if err != nil {
		if prev := newSources[id]; prev != nil {
			clone := prev.clone()
			clone.Config = *target
			clone.LastError = err.Error()
			newSources[id] = clone
		} else {
			newSources[id] = &sourceState{Config: *target, LastError: err.Error()}
		}
		next := buildStoreFromSources(newSources)
		stateMu.Lock()
		current = next
		stateMu.Unlock()
		return err
	}

	base := &sourceState{Config: *target}
	if prev := old.sources[id]; prev != nil {
		base.Hits.Store(prev.Hits.Load())
	}
	base.LoadedEntries = fetched.loadedEntries
	base.UniqueEntries = fetched.uniqueEntries
	base.LastRefresh = time.Now()
	base.set = fetched.set
	newSources[id] = base

	next := buildStoreFromSources(newSources)
	stateMu.Lock()
	current = next
	stateMu.Unlock()
	runtime.GC()
	return nil
}
