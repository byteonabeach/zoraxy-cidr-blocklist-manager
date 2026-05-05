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
	"runtime"
	"strconv"
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
	refreshInterval  = 6 * time.Hour
	maxSourceSize    = 100 * 1024 * 1024
	maxLines         = 5000000
)

var pluginSpec = plugin.IntroSpect{
	ID:                    pluginID,
	Name:                  "MultiCIDR Shield",
	Author:                "byteonabeach",
	AuthorContact:         "",
	Description:           "Blocks incoming IPs/CIDRs from user-managed remote blocklist sources. Add any URL pointing to a plain-text CIDR list and the plugin will download, parse, and enforce it automatically.",
	URL:                   pluginDisplayURL,
	Type:                  plugin.PluginType_Router,
	VersionMajor:          0,
	VersionMinor:          1,
	VersionPatch:          1,
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
	set           *ipSet
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
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
		"::1/128", "fe80::/10", "fc00::/7", "ff00::/8",
	} {
		_, network, _ := net.ParseCIDR(cidr)
		privateNets = append(privateNets, network)
	}
	current = &store{
		sources:   map[string]*sourceState{},
		lastBuild: time.Now(),
	}
}

func main() {
	configSpec, err := plugin.ServeAndRecvSpec(&pluginSpec)
	if err != nil {
		log.Fatal("[shield] Failed to receive configure spec:", err)
	}

	initConfigPath()
	if err := loadConfig(); err != nil {
		log.Printf("[shield] Warning: could not load config: %v", err)
	}
	normaliseConfigURLs()

	if len(appCfg.Sources) > 0 {
		if err := refreshAllSources(); err != nil {
			log.Printf("[shield] Initial refresh finished with issues: %v", err)
		}
	} else {
		log.Println("[shield] No sources configured yet — add URLs via the UI.")
	}

	go func() {
		ticker := time.NewTicker(refreshInterval)
		defer ticker.Stop()
		for range ticker.C {
			if err := refreshAllSources(); err != nil {
				log.Printf("[shield] Scheduled refresh finished with issues: %v", err)
			}
		}
	}()

	mux := http.NewServeMux()
	router := plugin.NewPathRouter()

	router.RegisterDynamicSniffHandler("/sniff", mux, sniffHandler)
	router.RegisterDynamicCaptureHandle("/block", mux, blockHandler)

	uiRouter := plugin.NewPluginEmbedUIRouter(pluginID, &uiFiles, "/ui", "/ui")
	uiRouter.RegisterTerminateHandler(func() {
		log.Println("[shield] Plugin terminated by Zoraxy")
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
	log.Printf("[shield] Plugin listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func initConfigPath() {
	exe, err := os.Executable()
	if err != nil {
		configPath = "multicidr-shield.config.json"
		return
	}
	configPath = filepath.Join(filepath.Dir(exe), "multicidr-shield.config.json")
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

func normaliseConfigURLs() {
	configMu.Lock()
	defer configMu.Unlock()
	changed := false
	for i := range appCfg.Sources {
		if strings.TrimSpace(appCfg.Sources[i].ID) == "" {
			appCfg.Sources[i].ID = newSourceID()
			changed = true
		}
		norm := normalizeSourceURL(appCfg.Sources[i].URL)
		if norm != appCfg.Sources[i].URL {
			appCfg.Sources[i].URL = norm
			changed = true
		}
	}
	if changed {
		_ = saveConfigLocked()
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
	return fmt.Sprintf("src-%d", time.Now().UnixNano())
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

func getClientIP(req *plugin.DynamicSniffForwardRequest) string {
	if xff := req.Header["X-Forwarded-For"]; len(xff) > 0 && xff[0] != "" {
		ips := strings.Split(xff[0], ",")
		return strings.TrimSpace(ips[0])
	}
	if xri := req.Header["X-Real-Ip"]; len(xri) > 0 && xri[0] != "" {
		return strings.TrimSpace(xri[0])
	}
	ipStr, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return ipStr
}

func sniffHandler(req *plugin.DynamicSniffForwardRequest) plugin.SniffResult {
	ipStr := getClientIP(req)
	addr, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil || shouldSkipAddr(addr) {
		return plugin.SniffResultSkip
	}

	stateMu.RLock()
	defer stateMu.RUnlock()

	s := current
	blocked, matched := s.matches(addr)

	if !blocked {
		return plugin.SniffResultSkip
	}

	blockedCount.Add(1)
	for _, id := range matched {
		if src, ok := s.sources[id]; ok && src != nil {
			src.Hits.Add(1)
		}
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

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
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
			log.Printf("[shield] Manual refresh completed with issues: %v", err)
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
			log.Printf("[shield] Source %s initial fetch failed: %v", id, err)
		}
	}(newID)

	writeJSON(w, map[string]string{"status": "ok", "id": newID})
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
				log.Printf("[shield] Source %s re-fetch failed: %v", id, err)
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
				log.Printf("[shield] Refresh-all: %v", err)
			}
			return
		}
		if err := refreshOneSource(id); err != nil {
			log.Printf("[shield] Refresh source %s: %v", id, err)
		}
	}(req.ID)
	writeJSON(w, map[string]string{"status": "refresh_started"})
}

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

func fetchSource(rawURL string) (*fetchedSource, error) {
	transport := &http.Transport{
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 5 * time.Second,
		DisableKeepAlives:     true,
	}
	client := &http.Client{
		Timeout:   120 * time.Second,
		Transport: transport,
	}
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from server", resp.StatusCode)
	}

	if cl := resp.Header.Get("Content-Length"); cl != "" {
		size, _ := strconv.ParseInt(cl, 10, 64)
		if size > maxSourceSize {
			return nil, fmt.Errorf("file too large (%d bytes, max %d)", size, maxSourceSize)
		}
	}

	ct := resp.Header.Get("Content-Type")
	if strings.Contains(strings.ToLower(ct), "text/html") {
		return nil, fmt.Errorf("invalid content type: %s (expected plain text)", ct)
	}

	return parseSourceReader(io.LimitReader(resp.Body, maxSourceSize))
}

func parseSourceReader(r io.Reader) (*fetchedSource, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024), 1024*1024)

	result := &fetchedSource{
		set: newIPSet(),
	}
	loaded := 0
	valid := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}
		if idx := strings.IndexAny(line, "#;"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}

		loaded++
		if loaded > maxLines {
			break
		}

		prefix, err := parsePrefix(line)
		if err != nil {
			if loaded == 50 && valid < 5 {
				return nil, fmt.Errorf("file does not appear to be a valid CIDR/IP list")
			}
			continue
		}

		valid++
		result.set.Insert(prefix)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if loaded > 10 && valid == 0 {
		return nil, fmt.Errorf("file contains no valid IPs/CIDRs")
	}

	result.loadedEntries = loaded
	result.uniqueEntries = result.set.Count()
	return result, nil
}

func parsePrefix(line string) (netip.Prefix, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return netip.Prefix{}, errors.New("empty")
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
	return netip.PrefixFrom(addr, addr.BitLen()).Masked(), nil
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

func snapshotStore() *store {
	stateMu.RLock()
	defer stateMu.RUnlock()
	return current
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

func autoNameFromURL(raw string) string {
	if raw == "" {
		return "Unnamed Source"
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	host := u.Host
	path := strings.Trim(u.Path, "/")
	if path == "" {
		return host
	}
	parts := strings.Split(path, "/")
	last := parts[len(parts)-1]
	if last == "" && len(parts) > 1 {
		last = parts[len(parts)-2]
	}
	if len(last) > 48 {
		last = last[:48]
	}
	if host != "" {
		return fmt.Sprintf("%s — %s", host, last)
	}
	return last
}

func decodeJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(dst)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
