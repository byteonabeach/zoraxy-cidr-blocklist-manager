package main

import (
	"net"
	"net/netip"
	"strings"

	plugin "github.com/byteonabeach/zoraxy-multicidr-shield/mod/zoraxy_plugin"
)

var privateNets []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
		"::1/128", "fe80::/10", "fc00::/7", "ff00::/8",
	} {
		_, network, _ := net.ParseCIDR(cidr)
		privateNets = append(privateNets, network)
	}
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
