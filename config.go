package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type sourceConfig struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
}

type appConfig struct {
	Sources []sourceConfig `json:"sources"`
}

var (
	configMu   sync.Mutex
	appCfg     appConfig
	configPath string
)

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
