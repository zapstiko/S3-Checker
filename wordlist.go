package main

import (
	"bufio"
	"context"
	_ "embed"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

//go:embed common_bucket_prefixes.txt
var embeddedCommon string

//go:embed wordlists/services.txt
var embeddedServices string

//go:embed wordlists/environments.txt
var embeddedEnvironments string

//go:embed wordlists/objects.txt
var embeddedObjects string

type components struct {
	common   []string
	services []string
	envs     []string
	objects  []string
}

func loadEmbeddedComponents() (*components, error) {
	read := func(name, data string) ([]string, error) {
		lines, err := readLinesReader(strings.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		return lines, nil
	}

	common, err := read("common_bucket_prefixes.txt", embeddedCommon)
	if err != nil {
		return nil, err
	}
	services, err := read("wordlists/services.txt", embeddedServices)
	if err != nil {
		return nil, err
	}
	envs, err := read("wordlists/environments.txt", embeddedEnvironments)
	if err != nil {
		return nil, err
	}
	objects, err := read("wordlists/objects.txt", embeddedObjects)
	if err != nil {
		return nil, err
	}
	return &components{common: cleanTokens(common), services: cleanTokens(services), envs: cleanTokens(envs), objects: objects}, nil
}

func readLinesFile(path string) ([]string, error) {
	if path == "-" {
		return readLinesReader(os.Stdin)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readLinesReader(f)
}

func readLinesReader(r io.Reader) ([]string, error) {
	var out []string
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "\ufeff"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, scanner.Err()
}

// loadWordlist supports local files, HTTP(S) URLs, and stdin ("-").
func loadWordlist(source string) ([]string, error) {
	source = strings.TrimSpace(source)
	switch {
	case source == "-":
		return readLinesReader(os.Stdin)
	case strings.HasPrefix(source, "http://"), strings.HasPrefix(source, "https://"):
		return fetchWordlistURL(source)
	default:
		return readLinesFile(source)
	}
}

func fetchWordlistURL(source string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", fmt.Sprintf("s3-checker/%s (+https://github.com/zapstiko/S3-Checker)", version))
	req.Header.Set("Accept", "text/plain,*/*")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, source)
	}
	if ct := strings.ToLower(resp.Header.Get("Content-Type")); strings.Contains(ct, "text/html") {
		return nil, fmt.Errorf("%s returned HTML; use a raw file URL", source)
	}
	const maxWordlistSize = 200 << 20 // 200 MiB
	if resp.ContentLength > maxWordlistSize {
		return nil, fmt.Errorf("wordlist is too large (%d bytes)", resp.ContentLength)
	}
	lines, err := readLinesReader(io.LimitReader(resp.Body, maxWordlistSize))
	if err != nil {
		return nil, err
	}
	return lines, nil
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func mergeUnique(lists ...[]string) []string {
	var all []string
	for _, list := range lists {
		all = append(all, list...)
	}
	return dedupeStrings(all)
}

var tokenRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*[a-z0-9]$`)

func sanitizeWord(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "*.")
	s = strings.ReplaceAll(s, "_", "-")
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, "\t", "-")
	s = strings.Trim(s, ".-")
	return s
}

func cleanTokens(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		w := sanitizeWord(raw)
		if w == "" || len(w) > 63 || strings.Contains(w, "..") {
			continue
		}
		if !tokenRe.MatchString(w) {
			continue
		}
		if _, ok := seen[w]; ok {
			continue
		}
		seen[w] = struct{}{}
		out = append(out, w)
	}
	return out
}

var (
	bucketNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	ipv4Re       = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
)

// validBucketName enforces the AWS S3 bucket naming rules that matter for
// anonymous discovery. Dotted names are accepted; callers use path-style URLs
// for them to avoid TLS certificate mismatches.
func validBucketName(name string) bool {
	if len(name) < 3 || len(name) > 63 {
		return false
	}
	if !bucketNameRe.MatchString(name) {
		return false
	}
	if strings.Contains(name, "..") {
		return false
	}
	if strings.HasPrefix(name, "xn--") {
		return false
	}
	if strings.HasSuffix(name, "-s3alias") || strings.HasSuffix(name, "--ol-s3") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	if ipv4Re.MatchString(name) {
		validIP := true
		for _, part := range strings.Split(name, ".") {
			n, _ := strconv.Atoi(part)
			if n > 255 {
				validIP = false
				break
			}
		}
		if validIP {
			return false
		}
	}
	return true
}

// normalizeCandidates sanitizes, validates, and deduplicates bucket names.
func normalizeCandidates(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		name := sanitizeWord(raw)
		if !validBucketName(name) {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

// targetVariants turns a brand, hostname, or URL into safe bucket prefixes.
func targetVariants(target string) []string {
	raw := strings.TrimSpace(strings.ToLower(target))
	if raw == "" {
		return nil
	}
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil {
			raw = u.Hostname()
		}
	}
	raw = strings.TrimPrefix(raw, "*.")
	raw = strings.TrimSuffix(raw, ".")
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	if i := strings.IndexAny(raw, "/?#"); i >= 0 {
		raw = raw[:i]
	}
	raw = sanitizeWord(raw)
	if raw == "" {
		return nil
	}

	seen := make(map[string]struct{})
	var variants []string
	add := func(v string) {
		v = sanitizeWord(v)
		if !validBucketName(v) {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		variants = append(variants, v)
	}

	add(raw)
	base := raw
	if strings.HasPrefix(base, "www.") {
		base = strings.TrimPrefix(base, "www.")
		add(base)
	}
	if strings.Contains(base, ".") {
		labels := strings.Split(base, ".")
		if len(labels) > 0 {
			add(labels[0])
		}
		add(strings.Join(labels, "-"))
		add(strings.Join(labels, ""))
	}
	if strings.Contains(base, "-") {
		add(strings.ReplaceAll(base, "-", ""))
	}
	return variants
}

var (
	deepSuffixes = []string{
		"backup", "backups", "bak", "data", "db", "dumps", "files", "file",
		"assets", "asset", "static", "media", "images", "img", "uploads",
		"downloads", "docs", "documents", "logs", "archive", "archives",
		"export", "exports", "temp", "tmp", "old", "new", "dev", "test",
		"stage", "staging", "prod", "production", "qa", "uat", "preprod",
		"private", "public", "internal", "external", "config", "configs",
		"secrets", "keys", "certs", "users", "customers", "customer",
		"billing", "invoices", "payroll", "hr", "finance", "legal",
		"contracts", "reports", "research", "analytics", "data-lake",
		"warehouse", "ml", "models", "training", "snapshots", "releases",
		"artifacts", "builds", "cache", "static-assets", "web-assets",
	}
	deepYears = []string{
		"2015", "2016", "2017", "2018", "2019", "2020", "2021",
		"2022", "2023", "2024", "2025", "2026",
	}
	deepNumbers = func() []string {
		out := make([]string, 0, 20)
		for i := 1; i <= 20; i++ {
			out = append(out, strconv.Itoa(i))
		}
		return out
	}()
	deepRegions = []string{
		"us-east-1", "us-east-2", "us-west-1", "us-west-2",
		"eu-west-1", "eu-west-2", "eu-central-1", "eu-north-1",
		"ap-south-1", "ap-southeast-1", "ap-southeast-2",
		"ap-northeast-1", "sa-east-1", "ca-central-1",
	}
)

var standardEnvSet = map[string]struct{}{
	"dev": {}, "staging": {}, "test": {}, "qa": {}, "uat": {},
	"prod": {}, "production": {}, "preprod": {}, "sandbox": {}, "internal": {},
}

// pickWordBases selects the highest-signal prefixes for expensive word
// permutations. Env-only permutations are still generated for every variant.
func pickWordBases(bases []string) []string {
	var out []string
	for _, base := range bases {
		if !strings.Contains(base, ".") && !containsString(out, base) {
			out = append(out, base)
			if len(out) == 2 {
				return out
			}
		}
	}
	if len(out) < 2 {
		for _, base := range bases {
			if strings.Contains(base, "-") && !containsString(out, base) {
				out = append(out, base)
				break
			}
		}
	}
	if len(out) == 0 && len(bases) > 0 {
		out = append(out, bases[0])
	}
	return out
}

func containsString(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func filterStandardEnvs(envs []string) []string {
	var out []string
	for _, env := range envs {
		if _, ok := standardEnvSet[env]; ok {
			out = append(out, env)
		}
	}
	if len(out) == 0 {
		return envs
	}
	return out
}

// generateTargetCandidates expands a target into high-signal bucket names.
func generateTargetCandidates(target string, words, envs []string, deep bool) []string {
	bases := targetVariants(target)
	if len(bases) == 0 {
		return nil
	}
	words = cleanTokens(words)
	allEnvs := cleanTokens(envs)
	wordEnvs := allEnvs
	if !deep {
		wordEnvs = filterStandardEnvs(allEnvs)
	}
	wordBases := pickWordBases(bases)

	seen := make(map[string]struct{})
	add := func(s string) {
		s = sanitizeWord(s)
		if !validBucketName(s) {
			return
		}
		seen[s] = struct{}{}
	}

	// Cheap env-only permutations for every target variant.
	for _, base := range bases {
		add(base)
		for _, env := range allEnvs {
			add(base + "-" + env)
			add(env + "-" + base)
			add(base + "." + env)
		}
	}

	// Word permutations for the strongest one or two prefixes.
	for _, base := range wordBases {
		for _, word := range words {
			add(base + "-" + word)
			add(word + "-" + base)
			add(base + word)
			add(base + "." + word)

			for _, env := range wordEnvs {
				add(base + "-" + word + "-" + env)
				add(base + "-" + env + "-" + word)
				add(base + "-" + word + "." + env)
			}
			if deep {
				for _, year := range deepYears[len(deepYears)-7:] {
					add(base + "-" + word + "-" + year)
				}
			}
		}
	}

	if deep {
		for _, base := range bases {
			for _, year := range deepYears {
				add(base + "-" + year)
				add(year + "-" + base)
			}
			for _, number := range deepNumbers {
				add(base + "-" + number)
			}
			for _, region := range deepRegions {
				add(base + "-" + region)
			}
		}
	}

	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	return out
}
