package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// gatherOSINT collects bucket-name candidates from public sources. Free
// sources are opt-in because they disclose the target to third parties.
// GrayHatWarfare is used automatically when GHW_API_KEY is present.
func gatherOSINT(ctx context.Context, target string, enableFree, quiet bool, userAgent string) []string {
	keyword := osintKeyword(target)
	if keyword == "" {
		return nil
	}
	ghwKey := strings.TrimSpace(os.Getenv("GHW_API_KEY"))
	if !enableFree && ghwKey == "" {
		return nil
	}

	type sourceResult struct {
		name    string
		buckets []string
	}
	results := make(chan sourceResult, 4)
	var wg sync.WaitGroup

	start := func(name string, fn func() []string) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- sourceResult{name: name, buckets: fn()}
		}()
	}

	if enableFree {
		start("crt.sh", func() []string { return fetchCRTSh(ctx, keyword, userAgent) })
		start("osint.sh", func() []string { return fetchOsintSh(ctx, keyword, userAgent) })
	}
	if ghwKey != "" {
		start("grayhatwarfare", func() []string { return fetchGrayHatWarfare(ctx, keyword, ghwKey, userAgent) })
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	var all []string
	for result := range results {
		if !quiet && len(result.buckets) > 0 {
			fmt.Fprintf(os.Stderr, "[osint] %s: %d candidate(s)\n", result.name, len(result.buckets))
		}
		all = append(all, result.buckets...)
	}
	return normalizeCandidates(dedupeStrings(all))
}

// osintKeyword reduces a target to a stable search term.
func osintKeyword(target string) string {
	keyword := normalizeDomain(target)
	keyword = strings.TrimPrefix(keyword, "www.")
	if i := strings.Index(keyword, "."); i > 0 {
		keyword = keyword[:i]
	}
	keyword = sanitizeWord(keyword)
	if len(keyword) < 2 || !tokenRe.MatchString(keyword) {
		return ""
	}
	return keyword
}

func osintHTTPClient() *http.Client {
	return &http.Client{Timeout: 20 * time.Second}
}

func fetchCRTSh(ctx context.Context, keyword, userAgent string) []string {
	query := url.Values{}
	query.Set("q", "%"+keyword+"%.s3%.amazonaws.com")
	query.Set("output", "json")
	rawURL := "https://crt.sh/?" + query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := osintHTTPClient().Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var entries []struct {
		NameValue  string `json:"name_value"`
		CommonName string `json:"common_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&entries); err != nil {
		return nil
	}

	seen := make(map[string]struct{})
	var out []string
	for _, entry := range entries {
		names := strings.Fields(entry.NameValue + " " + entry.CommonName)
		for _, name := range names {
			name = strings.ToLower(strings.TrimSpace(name))
			if len(name) > 3 && name[0] == '*' {
				name = strings.TrimPrefix(name, "*.")
			}
			match := matchS3CNAME(name)
			if match == nil {
				continue
			}
			if _, ok := seen[match.bucket]; ok {
				continue
			}
			seen[match.bucket] = struct{}{}
			out = append(out, match.bucket)
			if len(out) >= 5000 {
				return out
			}
		}
	}
	return out
}

var osintS3URLRe = regexp.MustCompile(`[a-z0-9][a-z0-9.-]{2,62}\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com`)

func fetchOsintSh(ctx context.Context, target, userAgent string) []string {
	form := url.Values{}
	form.Set("keyword", target)
	form.Set("ext", "")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://osint.sh/buckets/", strings.NewReader(form.Encode()))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", userAgent)

	resp, err := osintHTTPClient().Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil
	}

	seen := make(map[string]struct{})
	var out []string
	for _, candidate := range osintS3URLRe.FindAllString(strings.ToLower(string(body)), -1) {
		match := matchS3CNAME(candidate)
		if match == nil {
			continue
		}
		if _, ok := seen[match.bucket]; ok {
			continue
		}
		seen[match.bucket] = struct{}{}
		out = append(out, match.bucket)
		if len(out) >= 1000 {
			break
		}
	}
	return out
}

func fetchGrayHatWarfare(ctx context.Context, target, apiKey, userAgent string) []string {
	endpoints := []string{
		"https://buckets.grayhatwarfare.com/api/v2/buckets?access_token=" + url.QueryEscape(apiKey) +
			"&keywords=" + url.QueryEscape(target) + "&limit=1000",
		"https://buckets.grayhatwarfare.com/api/v1/buckets?access_token=" + url.QueryEscape(apiKey) +
			"&keywords=" + url.QueryEscape(target),
	}
	for _, endpoint := range endpoints {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", userAgent)
		resp, err := osintHTTPClient().Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}
		var payload any
		err = json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&payload)
		resp.Body.Close()
		if err != nil {
			continue
		}
		names := walkBucketNames(payload)
		if len(names) > 0 {
			return normalizeCandidates(dedupeStrings(names))
		}
	}
	return nil
}

func walkBucketNames(value any) []string {
	var out []string
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for key, item := range x {
				switch strings.ToLower(key) {
				case "bucket", "bucketname", "bucket_name":
					if s, ok := item.(string); ok {
						out = append(out, s)
					}
				default:
					walk(item)
				}
			}
		case []any:
			for _, item := range x {
				walk(item)
			}
		}
	}
	walk(value)
	return out
}
