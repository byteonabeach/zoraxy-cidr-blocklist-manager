package main

import (
	"bufio"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	plugin "github.com/byteonabeach/zoraxy-multicidr-shield/mod/zoraxy_plugin"
)

//go:embed ui
var uiFiles embed.FS

const (
	pluginID         = "io.byteonabeach.zoraxy.cidr-manager"
	pluginDisplayURL = "https://github.com/byteonabeach/zoraxy-cidr-blocklist-manager"
	defaultSourceURL = "https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_critical_data-shield_ipv4_blocklist.txt"
	refreshInterval  = 6 * time.Hour
)

var pluginSpec = plugin.IntroSpect{
	ID:                    pluginID,
	Name:                  "byteonabeach MultiCIDR Shield",
	Author:                "byteonabeach",
	AuthorContact:         "",
	Description:           "Blocks incoming IPs/CIDRs from one or more user-managed blocklist sources. Inspired by Yax's Data-Shield plugin.",
	URL:                   pluginDisplayURL,
	Type:                  plugin.PluginType_Router,
	VersionMajor:          1,
	VersionMinor:          0,
	VersionPatch:          0,
	DynamicCaptureSniff:   "/sniff",
	DynamicCaptureIngress: "/block",
	UIPath:                "/ui",
}

type sourceConfig struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
}

type appConfig struct {
	Sources []sourceConfig `json:"sources"`
}

type sourceState struct {
	Config        sourceConfig   `json:"config"`
	LoadedEntries int            `json:"loaded_entries"`
	UniqueEntries int            `json:"unique_entries"`
	LastRefresh   time.Time      `json:"last_refresh"`
	LastError     string         `json:"last_error,omitempty"`
	Hits          atomic.Int64   `json:"-"`
	Prefixes      []netip.Prefix `json:"-"`
	trie4         *ipTrie
	trie6         *ipTrie
}

type store struct {
	sources     map[string]*sourceState
	trie4       *ipTrie
	trie6       *ipTrie
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
	ConfigPath    string          `json:"config_path"`
}

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

type fetchedSource struct {
	loadedEntries int
	uniqueEntries int
	prefixes      []netip.Prefix
	trie4         *ipTrie
	trie6         *ipTrie
}

var (
	stateMu sync.RWMutex
	current *store

	configMu   sync.Mutex
	appCfg     appConfig
	configPath string

	refreshing   atomic.Int32
	blockedCount atomic.Int64

	privateNets []*net.IPNet
)

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"100.64.0.0/10",
		"::1/128",
		"fe80::/10",
		"fc00::/7",
		"ff00::/8",
	} {
		_, network, _ := net.ParseCIDR(cidr)
		privateNets = append(privateNets, network)
	}
	current = &store{
		sources:   map[string]*sourceState{},
		trie4:     newIPTrie(32),
		trie6:     newIPTrie(128),
		lastBuild: time.Now(),
	}
}

func main() {
	configSpec, err := plugin.ServeAndRecvSpec(&pluginSpec)
	if err != nil {
		log.Fatal("[byteonabeach-shield] Failed to receive configure spec:", err)
	}

	initConfigPath()
	if err := loadConfig(); err != nil {
		log.Printf("[byteonabeach-shield] Warning: could not load config: %v", err)
	}
	ensureDefaultSource()
	if err := saveConfig(); err != nil {
		log.Printf("[byteonabeach-shield] Warning: could not save config: %v", err)
	}
	if err := refreshAllSources(); err != nil {
		log.Printf("[byteonabeach-shield] Initial refresh finished with issues: %v", err)
	}

	go func() {
		ticker := time.NewTicker(refreshInterval)
		defer ticker.Stop()
		for range ticker.C {
			if err := refreshAllSources(); err != nil {
				log.Printf("[byteonabeach-shield] Scheduled refresh finished with issues: %v", err)
			}
		}
	}()

	mux := http.NewServeMux()
	router := plugin.NewPathRouter()

	router.RegisterDynamicSniffHandler("/sniff", mux, sniffHandler)
	router.RegisterDynamicCaptureHandle("/block", mux, blockHandler)

	uiRouter := plugin.NewPluginEmbedUIRouter(pluginID, &uiFiles, "/ui", "/ui")
	uiRouter.RegisterTerminateHandler(func() {
		log.Println("[byteonabeach-shield] Plugin terminated by Zoraxy")
	}, mux)
	uiRouter.HandleFunc("/api/status", statusHandler, mux)
	uiRouter.HandleFunc("/api/refresh", refreshAllHandler, mux)
	uiRouter.HandleFunc("/api/reset-hits", resetHitsHandler, mux)
	uiRouter.HandleFunc("/api/source/add", addSourceHandler, mux)
	uiRouter.HandleFunc("/api/source/update", updateSourceHandler, mux)
	uiRouter.HandleFunc("/api/source/remove", removeSourceHandler, mux)
	uiRouter.HandleFunc("/api/source/refresh", refreshSourceHandler, mux)
	uiRouter.AttachHandlerToMux(mux)

	addr := fmt.Sprintf("127.0.0.1:%d", configSpec.Port)
	log.Printf("[byteonabeach-shield] Plugin listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func initConfigPath() {
	exe, err := os.Executable()
	if err != nil {
		configPath = "byteonabeach-multicidr-shield.config.json"
		return
	}
	configPath = filepath.Join(filepath.Dir(exe), "byteonabeach-multicidr-shield.config.json")
}

func loadConfig() error {
	configMu.Lock()
	defer configMu.Unlock()

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			appCfg = appConfig{}
			return nil
		}
		return err
	}
	return json.Unmarshal(data, &appCfg)
}

func saveConfig() error {
	configMu.Lock()
	defer configMu.Unlock()
	return saveConfigLocked()
}

func saveConfigLocked() error {
	tmp := configPath + ".tmp"
	data, err := json.MarshalIndent(appCfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, configPath)
}

func ensureDefaultSource() {
	configMu.Lock()
	defer configMu.Unlock()

	changed := false
	if len(appCfg.Sources) == 0 {
		appCfg.Sources = []sourceConfig{{
			ID:      newSourceID(),
			Name:    "Data-Shield Critical IPv4",
			URL:     defaultSourceURL,
			Enabled: true,
		}}
		changed = true
	}
	for i := range appCfg.Sources {
		if strings.TrimSpace(appCfg.Sources[i].ID) == "" {
			appCfg.Sources[i].ID = newSourceID()
			changed = true
		}
		appCfg.Sources[i].URL = normalizeSourceURL(appCfg.Sources[i].URL)
	}
	if changed {
		if err := saveConfigLocked(); err != nil {
			log.Printf("[byteonabeach-shield] Warning: could not save default config: %v", err)
		}
	}
}

func snapshotConfig() appConfig {
	configMu.Lock()
	defer configMu.Unlock()
	out := appCfg
	out.Sources = append([]sourceConfig(nil), appCfg.Sources...)
	return out
}

func updateConfig(mutator func(cfg *appConfig) error) error {
	configMu.Lock()
	defer configMu.Unlock()
	if err := mutator(&appCfg); err != nil {
		return err
	}
	return saveConfigLocked()
}

func newSourceID() string {
	return fmt.Sprintf("src-%d-%d", time.Now().UnixNano(), time.Now().UnixNano()%1_000_000)
}

func normalizeSourceURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if strings.EqualFold(u.Host, "github.com") {
		parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
		if len(parts) >= 5 && parts[2] == "blob" {
			owner, repo, branch := parts[0], parts[1], parts[3]
			file := strings.Join(parts[4:], "/")
			return fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", owner, repo, branch, file)
		}
	}
	return raw
}

func sniffHandler(req *plugin.DynamicSniffForwardRequest) plugin.SniffResult {
	ipStr, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		ipStr = req.RemoteAddr
	}

	addr, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil || shouldSkipAddr(addr) {
		return plugin.SniffResultSkip
	}

	stateMu.RLock()
	s := current
	blocked, matched := s.matches(addr)
	stateMu.RUnlock()

	if !blocked {
		return plugin.SniffResultSkip
	}

	blockedCount.Add(1)
	if len(matched) > 0 {
		stateMu.RLock()
		for _, id := range matched {
			if src, ok := current.sources[id]; ok && src != nil {
				src.Hits.Add(1)
			}
		}
		stateMu.RUnlock()
	}
	return plugin.SniffResultAccept
}

func shouldSkipAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	if addr.IsMulticast() || addr.IsLoopback() || addr.IsPrivate() || addr.IsUnspecified() {
		return true
	}
	if addr.Is4() {
		for _, n := range privateNets {
			if n.Contains(net.IP(addr.AsSlice())) {
				return true
			}
		}
	}
	if addr.Is6() {
		if addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
			return true
		}
	}
	return false
}

func blockHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = fmt.Fprint(w, `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>403 Forbidden</title>
  <style>
    body { font-family: sans-serif; max-width: 680px; margin: 4rem auto; padding: 0 1rem; text-align: center; line-height: 1.5; }
    h1 { color: #c0392b; margin-bottom: .5rem; }
    p { color: #555; }
  </style>
</head>
<body>
  <h1>403 Forbidden</h1>
  <p>Your IP address matched one of the configured CIDR sources and was denied by the byteonabeach MultiCIDR Shield.</p>
</body>
</html>`)
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	stateMu.RLock()
	s := current
	resp := statusResponse{ConfigPath: configPath, BlockedCount: blockedCount.Load()}
	if s != nil {
		resp.Loaded = len(s.sources) > 0
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
				SupportsIPv4:  src.trie4 != nil && src.trie4.Count() > 0,
				SupportsIPv6:  src.trie6 != nil && src.trie6.Count() > 0,
			})
			if src.Config.Enabled {
				resp.EnabledCount++
			} else {
				resp.DisabledCount++
			}
		}
	}
	stateMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func refreshAllHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	go func() {
		if err := refreshAllSources(); err != nil {
			log.Printf("[byteonabeach-shield] Manual refresh completed with issues: %v", err)
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
		http.Error(w, "Bad Request: URL is required", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		req.Name = autoNameFromURL(req.URL)
	}
	if err := updateConfig(func(cfg *appConfig) error {
		cfg.Sources = append(cfg.Sources, sourceConfig{
			ID:      newSourceID(),
			Name:    req.Name,
			URL:     req.URL,
			Enabled: req.Enabled,
		})
		return nil
	}); err != nil {
		http.Error(w, "Failed to save source: "+err.Error(), http.StatusInternalServerError)
		return
	}
	go func() {
		if err := refreshAllSources(); err != nil {
			log.Printf("[byteonabeach-shield] Source added, refresh completed with issues: %v", err)
		}
	}()
	writeJSON(w, map[string]string{"status": "ok"})
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
		http.Error(w, "Bad Request: missing id", http.StatusBadRequest)
		return
	}
	if err := updateConfig(func(cfg *appConfig) error {
		for i := range cfg.Sources {
			if cfg.Sources[i].ID != req.ID {
				continue
			}
			if req.Name != "" {
				cfg.Sources[i].Name = req.Name
			}
			if req.URL != "" {
				cfg.Sources[i].URL = req.URL
			}
			if req.Enabled != nil {
				cfg.Sources[i].Enabled = *req.Enabled
			}
			return nil
		}
		return errors.New("source not found")
	}); err != nil {
		http.Error(w, "Failed to update source: "+err.Error(), http.StatusBadRequest)
		return
	}
	go func() {
		if err := refreshAllSources(); err != nil {
			log.Printf("[byteonabeach-shield] Source updated, refresh completed with issues: %v", err)
		}
	}()
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
		http.Error(w, "Bad Request: missing id", http.StatusBadRequest)
		return
	}
	if err := updateConfig(func(cfg *appConfig) error {
		next := cfg.Sources[:0]
		for _, s := range cfg.Sources {
			if s.ID != req.ID {
				next = append(next, s)
			}
		}
		cfg.Sources = append([]sourceConfig(nil), next...)
		return nil
	}); err != nil {
		http.Error(w, "Failed to remove source: "+err.Error(), http.StatusBadRequest)
		return
	}
	go func() {
		if err := refreshAllSources(); err != nil {
			log.Printf("[byteonabeach-shield] Source removed, refresh completed with issues: %v", err)
		}
	}()
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
				log.Printf("[byteonabeach-shield] Refresh-all completed with issues: %v", err)
			}
			return
		}
		if err := refreshOneSource(id); err != nil {
			log.Printf("[byteonabeach-shield] Refresh source %s failed: %v", id, err)
		}
	}(req.ID)
	writeJSON(w, map[string]string{"status": "refresh_started"})
}

func autoNameFromURL(raw string) string {
	if raw == "" {
		return "Unnamed Source"
	}
	if u, err := url.Parse(raw); err == nil {
		host := u.Host
		path := strings.Trim(u.Path, "/")
		if path == "" {
			return host
		}
		parts := strings.Split(path, "/")
		last := parts[len(parts)-1]
		if len(last) > 40 {
			last = last[:40]
		}
		if host != "" {
			return fmt.Sprintf("%s/%s", host, last)
		}
		return last
	}
	return raw
}

func decodeJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(dst)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func refreshAllSources() error {
	if !refreshing.CompareAndSwap(0, 1) {
		return errors.New("refresh already in progress")
	}
	defer refreshing.Store(0)

	cfg := snapshotConfig()
	old := snapshotStore()
	newSources := make(map[string]*sourceState, len(cfg.Sources))
	unique := make(map[string]struct{}, 110000)
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
		base.Prefixes = append([]netip.Prefix(nil), fetched.prefixes...)
		base.trie4 = fetched.trie4
		base.trie6 = fetched.trie6
		newSources[sc.ID] = base

		for _, p := range fetched.prefixes {
			unique[p.String()] = struct{}{}
		}
	}

	next := buildStoreFromSources(newSources)
	stateMu.Lock()
	current = next
	stateMu.Unlock()

	log.Printf("[byteonabeach-shield] Refreshed %d sources, %d unique CIDRs/IPs", len(newSources), len(unique))
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
		return fmt.Errorf("source %q not found", id)
	}

	fetched, err := fetchSource(target.URL)
	if err != nil {
		newSources := cloneSourceMap(old.sources)
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

	newSources := cloneSourceMap(old.sources)
	base := &sourceState{Config: *target}
	if prev := old.sources[id]; prev != nil {
		base.Hits.Store(prev.Hits.Load())
	}
	base.LoadedEntries = fetched.loadedEntries
	base.UniqueEntries = fetched.uniqueEntries
	base.LastRefresh = time.Now()
	base.Prefixes = append([]netip.Prefix(nil), fetched.prefixes...)
	base.trie4 = fetched.trie4
	base.trie6 = fetched.trie6
	newSources[id] = base

	next := buildStoreFromSources(newSources)
	stateMu.Lock()
	current = next
	stateMu.Unlock()
	return nil
}

func fetchSource(rawURL string) (*fetchedSource, error) {
	client := &http.Client{Timeout: 45 * time.Second}
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}

	return parseSourceReader(resp.Body)
}

func parseSourceReader(r io.Reader) (*fetchedSource, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024), 1024*1024)

	result := &fetchedSource{
		trie4: newIPTrie(32),
		trie6: newIPTrie(128),
	}
	seen := make(map[string]struct{}, 65536)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if idx := strings.Index(line, ";"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}
		prefix, err := parsePrefix(line)
		if err != nil {
			continue
		}
		key := prefix.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result.prefixes = append(result.prefixes, prefix)
		if prefix.Addr().Is4() {
			result.trie4.Insert(prefix)
		} else {
			result.trie6.Insert(prefix)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	result.loadedEntries = len(result.prefixes)
	result.uniqueEntries = len(result.prefixes)
	return result, nil
}

func parsePrefix(line string) (netip.Prefix, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return netip.Prefix{}, errors.New("empty line")
	}
	if strings.Contains(line, "/") {
		p, err := netip.ParsePrefix(line)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	addr, err := netip.ParseAddr(line)
	if err != nil {
		return netip.Prefix{}, err
	}
	if addr.Is4() {
		return netip.PrefixFrom(addr, 32).Masked(), nil
	}
	return netip.PrefixFrom(addr, 128).Masked(), nil
}

func buildStoreFromSources(sources map[string]*sourceState) *store {
	if sources == nil {
		sources = map[string]*sourceState{}
	}
	next := &store{
		sources:     sources,
		trie4:       newIPTrie(32),
		trie6:       newIPTrie(128),
		uniqueCount: 0,
		lastBuild:   time.Now(),
	}
	unique := make(map[string]struct{}, 110000)
	for _, src := range sources {
		if src == nil || !src.Config.Enabled {
			continue
		}
		for _, p := range src.Prefixes {
			unique[p.String()] = struct{}{}
			if p.Addr().Is4() {
				next.trie4.Insert(p)
			} else {
				next.trie6.Insert(p)
			}
		}
	}
	next.uniqueCount = len(unique)
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

func snapshotStore() *store {
	stateMu.RLock()
	defer stateMu.RUnlock()
	return current
}

func (s *store) matches(addr netip.Addr) (bool, []string) {
	if s == nil {
		return false, nil
	}
	var trie *ipTrie
	if addr.Is4() {
		trie = s.trie4
	} else {
		trie = s.trie6
	}
	if trie == nil || !trie.Contains(addr) {
		return false, nil
	}
	var matched []string
	for id, src := range s.sources {
		if src == nil || !src.Config.Enabled {
			continue
		}
		var st *ipTrie
		if addr.Is4() {
			st = src.trie4
		} else {
			st = src.trie6
		}
		if st != nil && st.Contains(addr) {
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
		Prefixes:      append([]netip.Prefix(nil), s.Prefixes...),
		trie4:         s.trie4,
		trie6:         s.trie6,
	}
	out.Hits.Store(s.Hits.Load())
	return out
}

func (s *sourceState) toSummary() sourceSummary {
	if s == nil {
		return sourceSummary{}
	}
	return sourceSummary{
		ID:            s.Config.ID,
		Name:          s.Config.Name,
		URL:           s.Config.URL,
		Enabled:       s.Config.Enabled,
		LoadedEntries: s.LoadedEntries,
		UniqueEntries: s.UniqueEntries,
		LastRefresh:   s.LastRefresh,
		LastError:     s.LastError,
		Hits:          s.Hits.Load(),
		SupportsIPv4:  s.trie4 != nil && s.trie4.Count() > 0,
		SupportsIPv6:  s.trie6 != nil && s.trie6.Count() > 0,
	}
}
