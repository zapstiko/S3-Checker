package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const version = "v2.0.0"

// options holds the fully parsed runtime configuration.
type options struct {
	targets       []string
	bucketNames   []string
	domains       []string
	wordlist      string
	exact         bool
	deep          bool
	maxCandidates int
	concurrency   int
	rate          int
	timeout       time.Duration
	retries       int
	proxy         string
	provider      string
	region        string
	endpoint      string
	perms         bool
	objects       int
	output        string
	format        string
	noColor       bool
	noProgress    bool
	quiet         bool
	statusFilter  int
	exclude       map[int]struct{}
	osint         bool
	userAgent     string
	showVersion   bool
	followRegion  bool
	takeoverAll   bool
	prov          Provider
	objectKeys    []string
}

func main() {
	opts := parseFlags()
	if opts.showVersion {
		fmt.Printf("s3-checker %s\n", version)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	components, err := loadEmbeddedComponents()
	if err != nil {
		fatalf("loading embedded wordlists: %v", err)
	}
	opts.objectKeys = components.objects

	words := components.common
	if opts.wordlist != "" {
		words, err = loadWordlist(opts.wordlist)
		if err != nil {
			fatalf("loading wordlist: %v", err)
		}
		if len(words) == 0 {
			fatalf("wordlist %q contains no usable entries", opts.wordlist)
		}
	}

	if opts.exact && opts.wordlist == "" {
		fatalf("--exact requires -w/--wordlist")
	}
	if len(opts.targets) == 0 && len(opts.bucketNames) == 0 && !opts.exact && len(opts.domains) == 0 {
		printUsage()
		fatalf("no input supplied: use -t, -tL, -b, -bL, -w --exact, or -d")
	}

	reporter, err := newReporter(opts)
	if err != nil {
		fatalf("%v", err)
	}
	defer reporter.Close()

	var candidates []string
	candidates = append(candidates, opts.bucketNames...)

	switch {
	case opts.exact:
		candidates = append(candidates, words...)
	case len(opts.targets) > 0:
		baseWords := words
		if opts.deep {
			if opts.wordlist == "" {
				baseWords = mergeUnique(components.common, components.services)
			}
			baseWords = mergeUnique(baseWords, deepSuffixes)
		}
		for _, target := range opts.targets {
			candidates = append(candidates, generateTargetCandidates(target, baseWords, components.envs, opts.deep)...)
			candidates = append(candidates, gatherOSINT(ctx, target, opts.osint, opts.quiet, opts.userAgent)...)
		}
	}

	candidates = normalizeCandidates(candidates)
	sort.Strings(candidates)

	if opts.maxCandidates > 0 && len(candidates) > opts.maxCandidates {
		if !opts.quiet {
			fmt.Fprintf(os.Stderr, "[!] Candidate cap reached: using %d of %d candidates\n", opts.maxCandidates, len(candidates))
		}
		candidates = candidates[:opts.maxCandidates]
	}

	if len(candidates) == 0 && len(opts.domains) == 0 {
		fatalf("no valid bucket candidates were generated")
	}

	printBanner(opts, len(candidates))
	if len(candidates) > 100000 && !opts.quiet {
		fmt.Fprintf(os.Stderr, "[!] Large candidate set (%d). Consider -r, --max-candidates, or a narrower wordlist.\n", len(candidates))
	}

	checker := NewChecker(opts)
	start := time.Now()

	if len(candidates) > 0 {
		runBucketScan(ctx, checker, reporter, candidates, opts.concurrency)
	}
	if len(opts.domains) > 0 && ctx.Err() == nil {
		runTakeoverScan(ctx, checker, reporter, opts.domains, opts.concurrency)
	}

	reporter.Summary(time.Since(start))
	reporter.Close()

	if ctx.Err() != nil {
		os.Exit(130)
	}
}

// parseFlags registers short and long aliases for every option and resolves inputs.
func parseFlags() *options {
	var (
		target, targetList         string
		buckets, bucketList        string
		domains                    string
		wordlist                   string
		output, format             string
		proxy, provider, region    string
		endpoint, userAgent        string
		exclude                    string
		exact, deep                bool
		perms, osint               bool
		noColor, noProgress, quiet bool
		jsonOut, showVersion       bool
		followRegion, takeoverAll  bool
		maxCandidates, concurrency int
		rate, retries, objects     int
		statusFilter               int
		timeout                    time.Duration
	)

	// Target input.
	flag.StringVar(&target, "t", "", "target brand/domain (comma-separated)")
	flag.StringVar(&target, "target", "", "target brand/domain (comma-separated)")
	flag.StringVar(&targetList, "tL", "", "file containing targets")
	flag.StringVar(&targetList, "target-list", "", "file containing targets")
	flag.StringVar(&buckets, "b", "", "exact bucket names (comma-separated)")
	flag.StringVar(&buckets, "buckets", "", "exact bucket names (comma-separated)")
	flag.StringVar(&bucketList, "bL", "", "file containing exact bucket names")
	flag.StringVar(&bucketList, "bucket-list", "", "file containing exact bucket names")
	flag.StringVar(&domains, "d", "", "domain (or file) for S3 takeover checks")

	// Wordlist / permutation.
	flag.StringVar(&wordlist, "w", "", "custom wordlist (file, URL, or - for stdin)")
	flag.StringVar(&wordlist, "wordlist", "", "custom wordlist (file, URL, or - for stdin)")
	flag.BoolVar(&exact, "exact", false, "treat wordlist entries as exact bucket names")
	flag.BoolVar(&deep, "deep", false, "deep permutations (services, years, regions, numbers)")
	flag.IntVar(&maxCandidates, "max-candidates", 0, "cap candidate count (0 = unlimited)")

	// Scanning.
	flag.IntVar(&concurrency, "c", 50, "worker concurrency")
	flag.IntVar(&concurrency, "concurrency", 50, "worker concurrency")
	flag.IntVar(&rate, "r", 0, "global requests/sec (0 = unlimited)")
	flag.IntVar(&rate, "rate", 0, "global requests/sec (0 = unlimited)")
	flag.DurationVar(&timeout, "timeout", 8*time.Second, "per-request timeout")
	flag.IntVar(&retries, "retries", 2, "retries for transient failures")
	flag.StringVar(&proxy, "proxy", "", "proxy URL (or use HTTP(S)_PROXY)")
	flag.StringVar(&provider, "provider", "aws", "aws|do|wasabi|linode|b2|scaleway|gcs|custom")
	flag.StringVar(&region, "region", "", "provider region")
	flag.StringVar(&endpoint, "endpoint", "", "custom endpoint; supports {bucket} and {region}")
	flag.BoolVar(&perms, "p", false, "enumerate ACL/policy/CORS/website and object exposure")
	flag.BoolVar(&perms, "perms", false, "enumerate ACL/policy/CORS/website and object exposure")
	flag.IntVar(&objects, "objects", 10, "max objects to list/probe in perms mode")
	flag.BoolVar(&followRegion, "follow-region", true, "follow S3 region redirects")
	flag.BoolVar(&osint, "osint", false, "enable free OSINT enrichment (crt.sh, osint.sh)")
	flag.StringVar(&userAgent, "user-agent", "", "custom User-Agent")

	// Output.
	flag.StringVar(&output, "o", "", "output file")
	flag.StringVar(&output, "output", "", "output file")
	flag.StringVar(&format, "f", "console", "output format: console|json|jsonl|csv")
	flag.StringVar(&format, "format", "console", "output format: console|json|jsonl|csv")
	flag.BoolVar(&jsonOut, "json", false, "shorthand for -f jsonl")
	flag.IntVar(&statusFilter, "s", 0, "only show this HTTP status")
	flag.IntVar(&statusFilter, "status", 0, "only show this HTTP status")
	flag.StringVar(&exclude, "e", "", "exclude HTTP status codes (comma-separated)")
	flag.StringVar(&exclude, "exclude", "", "exclude HTTP status codes (comma-separated)")
	flag.BoolVar(&noColor, "no-color", false, "disable colors")
	flag.BoolVar(&noProgress, "no-progress", false, "disable progress line")
	flag.BoolVar(&quiet, "quiet", false, "suppress banner, progress, and summary")
	flag.BoolVar(&takeoverAll, "takeover-all", false, "show non-vulnerable takeover results")
	flag.BoolVar(&showVersion, "v", false, "print version")
	flag.BoolVar(&showVersion, "version", false, "print version")

	flag.Usage = printUsage
	flag.Parse()

	if showVersion {
		return &options{showVersion: true}
	}
	if jsonOut {
		format = "jsonl"
	}
	format = normalizeFormat(format)
	if format == "" {
		fatalf("unsupported output format")
	}
	if concurrency < 1 || concurrency > 2000 {
		fatalf("concurrency must be between 1 and 2000")
	}
	if rate < 0 || rate > 1000000 {
		fatalf("rate must be between 0 and 1000000")
	}
	if timeout <= 0 {
		fatalf("timeout must be positive")
	}
	if retries < 0 || retries > 20 {
		fatalf("retries must be between 0 and 20")
	}
	if objects < 0 {
		fatalf("objects must be >= 0")
	}
	if maxCandidates < 0 {
		fatalf("max-candidates must be >= 0")
	}
	if proxy != "" {
		u, err := url.Parse(proxy)
		if err != nil || u.Host == "" {
			fatalf("invalid --proxy %q", proxy)
		}
	}
	if userAgent == "" {
		userAgent = fmt.Sprintf("s3-checker/%s (+https://github.com/zapstiko/S3-Checker)", version)
	}

	prov, err := resolveProvider(provider, endpoint, region)
	if err != nil {
		fatalf("%v", err)
	}

	opts := &options{
		wordlist:      wordlist,
		exact:         exact,
		deep:          deep,
		maxCandidates: maxCandidates,
		concurrency:   concurrency,
		rate:          rate,
		timeout:       timeout,
		retries:       retries,
		proxy:         proxy,
		provider:      prov.Name,
		region:        region,
		endpoint:      endpoint,
		perms:         perms,
		objects:       objects,
		output:        output,
		format:        format,
		noColor:       noColor,
		noProgress:    noProgress,
		quiet:         quiet,
		statusFilter:  statusFilter,
		exclude:       parseExcludeSet(exclude),
		osint:         osint,
		userAgent:     userAgent,
		followRegion:  followRegion,
		takeoverAll:   takeoverAll,
		prov:          prov,
	}

	opts.targets, err = collectValues(target, targetList)
	if err != nil {
		fatalf("reading targets: %v", err)
	}
	opts.bucketNames, err = collectValues(buckets, bucketList)
	if err != nil {
		fatalf("reading bucket list: %v", err)
	}
	opts.domains, err = collectDomains(domains)
	if err != nil {
		fatalf("reading domain list: %v", err)
	}
	return opts
}

func normalizeFormat(f string) string {
	switch strings.ToLower(strings.TrimSpace(f)) {
	case "", "console", "text", "txt":
		return "console"
	case "json":
		return "json"
	case "jsonl", "ndjson":
		return "jsonl"
	case "csv":
		return "csv"
	default:
		return ""
	}
}

func parseExcludeSet(input string) map[int]struct{} {
	out := make(map[int]struct{})
	for _, part := range strings.Split(input, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if code, err := strconv.Atoi(part); err == nil {
			out[code] = struct{}{}
		}
	}
	return out
}

// collectValues merges a comma-separated value with an optional file.
func collectValues(csvValue, filePath string) ([]string, error) {
	var out []string
	if csvValue != "" {
		for _, part := range strings.Split(csvValue, ",") {
			if v := strings.TrimSpace(part); v != "" {
				out = append(out, v)
			}
		}
	}
	if filePath != "" {
		lines, err := readLinesFile(filePath)
		if err != nil {
			return nil, err
		}
		out = append(out, lines...)
	}
	return dedupeStrings(out), nil
}

// collectDomains accepts a comma-separated list, a file path, or a single domain.
func collectDomains(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	if fi, err := os.Stat(value); err == nil && !fi.IsDir() {
		lines, err := readLinesFile(value)
		if err != nil {
			return nil, err
		}
		return dedupeStrings(lines), nil
	}
	var out []string
	for _, part := range strings.Split(value, ",") {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	return dedupeStrings(out), nil
}

func runBucketScan(ctx context.Context, checker *Checker, reporter *Reporter, candidates []string, concurrency int) {
	jobs := make(chan string, concurrency*2)
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case bucket, ok := <-jobs:
					if !ok {
						return
					}
					res := checker.Check(ctx, bucket)
					if ctx.Err() != nil {
						return
					}
					reporter.ReportBucket(res)
					reporter.Tick()
				}
			}
		}()
	}

feed:
	for _, bucket := range candidates {
		select {
		case <-ctx.Done():
			break feed
		case jobs <- bucket:
		}
	}
	close(jobs)
	wg.Wait()
}

func runTakeoverScan(ctx context.Context, checker *Checker, reporter *Reporter, domains []string, concurrency int) {
	if concurrency > 32 {
		concurrency = 32
	}
	if concurrency < 1 {
		concurrency = 1
	}

	jobs := make(chan string, concurrency)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case domain, ok := <-jobs:
					if !ok {
						return
					}
					res := checker.DetectTakeover(ctx, domain)
					if ctx.Err() != nil {
						return
					}
					reporter.ReportTakeover(res)
				}
			}
		}()
	}

feed:
	for _, domain := range domains {
		select {
		case <-ctx.Done():
			break feed
		case jobs <- domain:
		}
	}
	close(jobs)
	wg.Wait()
}

func printBanner(opts *options, candidateCount int) {
	if opts.quiet {
		return
	}
	banner := `    ____   _____      _____ _               _
  / ___| |___ /     / ____| |__   ___  ___| | _____ _ __
  \___ \   |_ \____| |    | '_ \ / _ \/ __| |/ / _ \ '__|
   ___) | ___) |____| |___ | | | |  __/ (__|   <  __/ |
  |____/ |____/      \____||_| |_|\___|\___|_|\_\___|_|

     s3-checker v2 — S3 Discovery & Exposure Audit
     Developer - Abu Raihan Biswas (zapstiko)
`
	fmt.Fprintln(os.Stderr, banner)
	fmt.Fprintf(os.Stderr, "[+] Provider       : %s\n", opts.provider)
	fmt.Fprintf(os.Stderr, "[+] Targets        : %d\n", len(opts.targets))
	fmt.Fprintf(os.Stderr, "[+] Candidates     : %d\n", candidateCount)
	fmt.Fprintf(os.Stderr, "[+] Domains        : %d\n", len(opts.domains))
	fmt.Fprintf(os.Stderr, "[+] Concurrency    : %d\n", opts.concurrency)
	if opts.rate > 0 {
		fmt.Fprintf(os.Stderr, "[+] Rate limit     : %d req/sec\n", opts.rate)
	} else {
		fmt.Fprintf(os.Stderr, "[+] Rate limit     : disabled\n")
	}
	if opts.perms {
		fmt.Fprintf(os.Stderr, "[+] Permissions    : enumeration enabled (read-only)\n")
	}
	if opts.statusFilter != 0 {
		fmt.Fprintf(os.Stderr, "[+] Status filter  : %d\n", opts.statusFilter)
	}
	if len(opts.exclude) > 0 {
		fmt.Fprintf(os.Stderr, "[+] Exclude codes  : enabled\n")
	}
	fmt.Fprintln(os.Stderr)
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `s3-checker %s
Fast AWS S3 bucket discovery, permission auditing, and takeover detection.

Usage:
  s3-checker -t <target> [options]
  s3-checker -b <bucket[,bucket...]> [options]
  s3-checker -w <file|url> --exact [options]
  s3-checker -d <domain|file> [options]

Target input:
  -t,  --target string        Target brand/domain (comma-separated)
  -tL, --target-list file     File containing targets
  -b,  --buckets string       Exact bucket names (comma-separated)
  -bL, --bucket-list file     File containing exact bucket names
  -d,  --domains string       Domain or file for S3 takeover checks

Wordlist:
  -w,  --wordlist string      Custom wordlist (file, URL, or - for stdin)
       --exact                Treat wordlist entries as exact bucket names
       --deep                 Deep permutations (services, years, regions, numbers)
       --max-candidates int   Cap candidate count (0 = unlimited)

Scanning:
  -c,  --concurrency int      Workers (default 50)
  -r,  --rate int             Global requests/sec (0 = unlimited)
       --timeout duration     Per-request timeout (default 8s)
       --retries int          Retries for transient failures (default 2)
       --proxy string         Proxy URL (or HTTP(S)_PROXY)
       --provider string      aws|do|wasabi|linode|b2|scaleway|gcs|custom
       --region string        Provider region
       --endpoint string      Custom endpoint; supports {bucket} and {region}
  -p,  --perms                Enumerate ACL/policy/CORS/website and object exposure
       --objects int          Max objects to list/probe in perms mode (0 disables, default 10)
       --osint                Enable free OSINT enrichment (crt.sh, osint.sh)
       --follow-region        Follow S3 region redirects (default true)
       --user-agent string    Custom User-Agent

Output:
  -o,  --output string        Output file
  -f,  --format string        console|json|jsonl|csv (default console)
       --json                 Shorthand for -f jsonl
  -s,  --status int           Only show this HTTP status
  -e,  --exclude string       Exclude HTTP status codes (comma-separated)
       --quiet                Suppress banner, progress, and summary
       --no-progress          Disable progress line
       --no-color             Disable colors
       --takeover-all         Show non-vulnerable takeover results
  -v,  --version              Print version

Examples:
  s3-checker -t example
  s3-checker -t example -p -r 25
  s3-checker -w https://raw.githubusercontent.com/zapstiko/S3-Checker/main/wordlists/s3-buckets-master.txt --exact
  s3-checker -b my-bucket,another-bucket -p -f json -o findings.json
  s3-checker -d domains.txt --takeover-all
`, version)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[!] "+format+"\n", args...)
	os.Exit(1)
}
