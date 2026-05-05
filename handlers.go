package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type addSourceRequest struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
}

type updateSourceRequest struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled *bool  `json:"enabled"`
}

type idRequest struct {
	ID string `json:"id"`
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	stateMu.RLock()
	s := current
	resp := statusResponse{
		BlockedCount: blockedCount.Load(),
		Refreshing:   refreshing.Load() == 1,
	}
	if s != nil {
		resp.SourceCount = len(s.sources)
		resp.UniqueEntries = s.uniqueCount
		resp.LastRefresh = s.lastBuild
		resp.Sources = make([]sourceSummary, 0, len(s.sources))
		for _, src := range s.sources {
			if src == nil {
				continue
			}
			resp.Sources = append(resp.Sources, sourceSummary{
				ID:            src.Config.ID,
				Name:          src.Config.Name,
				URL:           src.Config.URL,
				Enabled:       src.Config.Enabled,
				LoadedEntries: src.LoadedEntries,
				UniqueEntries: src.UniqueEntries,
				LastRefresh:   src.LastRefresh,
				LastError:     src.LastError,
				Hits:          src.Hits.Load(),
				SupportsIPv4:  src.set != nil && (len(src.set.single4) > 0 || src.set.trie4.Count() > 0),
				SupportsIPv6:  src.set != nil && (len(src.set.single6) > 0 || src.set.trie6.Count() > 0),
			})
			if src.Config.Enabled {
				resp.EnabledCount++
			} else {
				resp.DisabledCount++
			}
		}
		resp.Loaded = resp.EnabledCount > 0 && resp.UniqueEntries > 0
	}
	stateMu.RUnlock()

	cfg := snapshotConfig()
	orderMap := make(map[string]int, len(cfg.Sources))
	for i, sc := range cfg.Sources {
		orderMap[sc.ID] = i
	}
	sortSources(resp.Sources, orderMap)

	writeJSON(w, resp)
}

func sortSources(ss []sourceSummary, order map[string]int) {
	for i := 0; i < len(ss); i++ {
		for j := i + 1; j < len(ss); j++ {
			oi, oj := order[ss[i].ID], order[ss[j].ID]
			if oi > oj {
				ss[i], ss[j] = ss[j], ss[i]
			}
		}
	}
}

func refreshAllHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	go func() {
		if err := refreshAllSources(); err != nil {
			fmt.Printf("[shield] Manual refresh completed with issues: %v\n", err)
		}
	}()
	writeJSON(w, map[string]string{"status": "refresh_started"})
}

func resetHitsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	stateMu.RLock()
	for _, src := range current.sources {
		if src != nil {
			src.Hits.Store(0)
		}
	}
	stateMu.RUnlock()
	blockedCount.Store(0)
	writeJSON(w, map[string]string{"status": "ok"})
}

func addSourceHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var req addSourceRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "Bad Request: "+err.Error(), http.StatusBadRequest)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.URL = normalizeSourceURL(req.URL)
	if req.URL == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		req.Name = autoNameFromURL(req.URL)
	}
	var newID string
	if err := updateConfig(func(cfg *appConfig) error {
		for _, s := range cfg.Sources {
			if s.URL == req.URL {
				return errors.New("a source with this URL already exists")
			}
		}
		newID = newSourceID()
		cfg.Sources = append(cfg.Sources, sourceConfig{
			ID:      newID,
			Name:    req.Name,
			URL:     req.URL,
			Enabled: req.Enabled,
		})
		return nil
	}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	go func(id string) {
		if err := refreshOneSource(id); err != nil {
			fmt.Printf("[shield] Source %s initial fetch failed: %v\n", id, err)
		}
	}(newID)
	writeJSON(w, map[string]string{"status": "ok", "id": newID})
}

func updateSourceHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var req updateSourceRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "Bad Request: "+err.Error(), http.StatusBadRequest)
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	req.Name = strings.TrimSpace(req.Name)
	req.URL = normalizeSourceURL(req.URL)
	if req.ID == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	urlChanged := false
	if err := updateConfig(func(cfg *appConfig) error {
		for i := range cfg.Sources {
			if cfg.Sources[i].ID != req.ID {
				continue
			}
			if req.Name != "" {
				cfg.Sources[i].Name = req.Name
			}
			if req.URL != "" && req.URL != cfg.Sources[i].URL {
				cfg.Sources[i].URL = req.URL
				urlChanged = true
			}
			if req.Enabled != nil {
				cfg.Sources[i].Enabled = *req.Enabled
			}
			return nil
		}
		return errors.New("source not found")
	}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if urlChanged {
		go func(id string) {
			if err := refreshOneSource(id); err != nil {
				fmt.Printf("[shield] Source %s re-fetch failed: %v\n", id, err)
			}
		}(req.ID)
	} else {
		syncStoreWithConfig()
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func removeSourceHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var req idRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "Bad Request: "+err.Error(), http.StatusBadRequest)
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	if err := updateConfig(func(cfg *appConfig) error {
		next := cfg.Sources[:0]
		found := false
		for _, s := range cfg.Sources {
			if s.ID == req.ID {
				found = true
				continue
			}
			next = append(next, s)
		}
		if !found {
			return errors.New("source not found")
		}
		cfg.Sources = append([]sourceConfig(nil), next...)
		return nil
	}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	syncStoreWithConfig()
	writeJSON(w, map[string]string{"status": "ok"})
}

func refreshSourceHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var req idRequest
	_ = decodeJSON(r, &req)
	req.ID = strings.TrimSpace(req.ID)
	go func(id string) {
		if id == "" {
			if err := refreshAllSources(); err != nil {
				fmt.Printf("[shield] Refresh-all: %v\n", err)
			}
			return
		}
		if err := refreshOneSource(id); err != nil {
			fmt.Printf("[shield] Refresh source %s: %v\n", id, err)
		}
	}(req.ID)
	writeJSON(w, map[string]string{"status": "refresh_started"})
}

func blockHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprint(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>403 Forbidden</title>
<style>
body{font-family:sans-serif;max-width:580px;margin:5rem auto;padding:0 1.5rem;text-align:center}
h1{font-size:2.5rem;color:#c0392b;margin-bottom:.5rem}
p{color:#666;line-height:1.6}
</style>
</head>
<body>
<h1>403 Forbidden</h1>
<p>Your IP address is listed in one of the configured CIDR blocklists and has been denied access by the MultiCIDR Shield plugin.</p>
</body>
</html>`)
}

func decodeJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(dst)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
