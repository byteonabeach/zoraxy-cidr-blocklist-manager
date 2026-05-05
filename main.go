package main

import (
	"embed"
	"fmt"
	"log"
	"net/http"
	"time"

	plugin "github.com/byteonabeach/zoraxy-multicidr-shield/mod/zoraxy_plugin"
)

//go:embed ui
var uiFiles embed.FS

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
