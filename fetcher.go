package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type fetchedSource struct {
	loadedEntries int
	uniqueEntries int
	set           *ipSet
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
