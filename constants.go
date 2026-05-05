package main

import "time"

const (
	pluginID         = "io.byteonabeach.zoraxy.cidr-manager"
	pluginDisplayURL = "https://github.com/byteonabeach/zoraxy-cidr-blocklist-manager"
	refreshInterval  = 6 * time.Hour
	maxSourceSize    = 100 * 1024 * 1024
	maxLines         = 5000000
)
