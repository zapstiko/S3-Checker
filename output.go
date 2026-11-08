package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorDim    = "\033[2m"
	colorBold   = "\033[1m"
	colorReset  = "\033[0m"
)

var csvHeader = []string{
	"type", "bucket", "domain", "cname", "url", "status", "http_status",
	"region", "provider", "error_code", "message", "public_acl",
	"public_acl_write", "public_policy", "public_write", "cors_wildcard",
	"website", "listed_objects", "objects", "configs",
}

type Stats struct {
	Checked         int
	Found           int
	Public          int
	Private         int
	Exists          int
	Errors          int
	TakeoverChecked int
	Takeovers       int
	Regions         map[string]int
}

type Reporter struct {
	mu         sync.Mutex
	opts       *options
	format     string
	humanOut   io.Writer
	structBuf  *bufio.Writer
	consoleBuf *bufio.Writer
	csvOut     *csv.Writer
	file       *os.File
	color      bool
	progress   bool

	lastProgress  time.Time
	wroteProgress bool
	jsonFirst     bool
	closed        bool
	stats         Stats
}

func newReporter(opts *options) (*Reporter, error) {
	r := &Reporter{
		opts:   opts,
		format: opts.format,
		stats:  Stats{Regions: make(map[string]int)},
	}
	if !opts.noColor && os.Getenv("NO_COLOR") == "" && isTerminal(os.Stdout) {
		r.color = true
	}
	if !opts.noProgress && !opts.quiet && isTerminal(os.Stderr) {
		r.progress = true
	}

	switch opts.format {
	case "console":
		r.humanOut = os.Stdout
		if opts.output != "" {
			f, err := os.Create(opts.output)
			if err != nil {
				return nil, fmt.Errorf("creating output file: %w", err)
			}
			r.file = f
			r.consoleBuf = bufio.NewWriter(f)
		}
	default:
		var out io.Writer = os.Stdout
		if opts.output != "" {
			f, err := os.Create(opts.output)
			if err != nil {
				return nil, fmt.Errorf("creating output file: %w", err)
			}
			r.file = f
			out = f
			r.humanOut = os.Stdout
		} else {
			// Keep stdout machine-parseable when no file is used.
			r.humanOut = io.Discard
		}
		r.structBuf = bufio.NewWriter(out)
		if opts.format == "json" {
			r.jsonFirst = true
			_, _ = r.structBuf.WriteString("[\n")
		}
		if opts.format == "csv" {
			r.csvOut = csv.NewWriter(r.structBuf)
			_ = r.csvOut.Write(csvHeader)
		}
	}
	return r, nil
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func (r *Reporter) ReportBucket(res BucketResult) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.stats.Checked++
	if res.Exists {
		r.stats.Found++
	}
	switch res.Status {
	case StatusPublic:
		r.stats.Public++
	case StatusPrivate:
		r.stats.Private++
	case StatusExists:
		r.stats.Exists++
	case StatusError:
		r.stats.Errors++
	}
	if res.Region != "" {
		r.stats.Regions[res.Region]++
	} else if res.Exists {
		r.stats.Regions["unknown"]++
	}

	interesting := res.Exists
	if !interesting && r.opts.statusFilter != 0 && res.HTTPStatus == r.opts.statusFilter {
		interesting = true
	}
	if !interesting {
		return
	}
	if r.opts.statusFilter != 0 && res.HTTPStatus != r.opts.statusFilter {
		return
	}
	if _, excluded := r.opts.exclude[res.HTTPStatus]; excluded {
		return
	}

	r.clearProgressLocked()
	fmt.Fprintln(r.humanOut, bucketLine(res, r.color))
	if r.consoleBuf != nil {
		fmt.Fprintln(r.consoleBuf, bucketLine(res, false))
	}
	switch r.format {
	case "json":
		r.writeJSONLocked(res)
	case "jsonl":
		r.writeJSONLocked(res)
	case "csv":
		r.writeBucketCSVLocked(res)
	}
	r.flushLocked()
}

func (r *Reporter) ReportTakeover(res TakeoverResult) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.stats.TakeoverChecked++
	if res.Status == TakeoverVulnerable {
		r.stats.Takeovers++
	}
	if !r.opts.takeoverAll && res.Status != TakeoverVulnerable {
		return
	}

	r.clearProgressLocked()
	fmt.Fprintln(r.humanOut, takeoverLine(res, r.color))
	if r.consoleBuf != nil {
		fmt.Fprintln(r.consoleBuf, takeoverLine(res, false))
	}
	switch r.format {
	case "json", "jsonl":
		r.writeJSONLocked(res)
	case "csv":
		r.writeTakeoverCSVLocked(res)
	}
	r.flushLocked()
}

func (r *Reporter) Tick() {
	if !r.progress {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if now.Sub(r.lastProgress) < 150*time.Millisecond {
		return
	}
	r.lastProgress = now
	fmt.Fprintf(os.Stderr, "\r\033[K[+] checked %d | found %d", r.stats.Checked, r.stats.Found)
	r.wroteProgress = true
}

func (r *Reporter) Summary(elapsed time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.clearProgressLocked()
	if r.opts.quiet {
		return
	}
	if elapsed <= 0 {
		elapsed = time.Millisecond
	}
	rate := float64(r.stats.Checked) / elapsed.Seconds()

	header := fmt.Sprintf("[+] Scan complete in %s", elapsed.Round(time.Millisecond))
	if !r.opts.noColor && os.Getenv("NO_COLOR") == "" && isTerminal(os.Stderr) {
		header = fmt.Sprintf("%s[+] Scan complete%s in %s", colorBold, colorReset, elapsed.Round(time.Millisecond))
	}
	fmt.Fprintf(os.Stderr, "\n%s", header)
	fmt.Fprintf(os.Stderr, "\n[+] Checked %d bucket(s) at %.1f/sec", r.stats.Checked, rate)
	fmt.Fprintf(os.Stderr, "\n[+] Found %d (public=%d private=%d exists=%d errors=%d)",
		r.stats.Found, r.stats.Public, r.stats.Private, r.stats.Exists, r.stats.Errors)
	if r.stats.TakeoverChecked > 0 {
		fmt.Fprintf(os.Stderr, "\n[+] Takeover checks %d (vulnerable=%d)",
			r.stats.TakeoverChecked, r.stats.Takeovers)
	}
	if len(r.stats.Regions) > 0 {
		type regionCount struct {
			region string
			count  int
		}
		var regions []regionCount
		for region, count := range r.stats.Regions {
			regions = append(regions, regionCount{region, count})
		}
		sort.Slice(regions, func(i, j int) bool {
			if regions[i].count == regions[j].count {
				return regions[i].region < regions[j].region
			}
			return regions[i].count > regions[j].count
		})
		if len(regions) > 8 {
			regions = regions[:8]
		}
		var parts []string
		for _, rc := range regions {
			parts = append(parts, fmt.Sprintf("%s=%d", rc.region, rc.count))
		}
		fmt.Fprintf(os.Stderr, "\n[+] Regions: %s", strings.Join(parts, " "))
	}
	fmt.Fprintln(os.Stderr)
}

func (r *Reporter) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	r.clearProgressLocked()

	if r.format == "json" && r.structBuf != nil {
		if r.jsonFirst {
			_, _ = r.structBuf.WriteString("]\n")
		} else {
			_, _ = r.structBuf.WriteString("\n]\n")
		}
	}
	if r.csvOut != nil {
		r.csvOut.Flush()
	}
	if r.structBuf != nil {
		_ = r.structBuf.Flush()
	}
	if r.consoleBuf != nil {
		_ = r.consoleBuf.Flush()
	}
	if r.file != nil {
		_ = r.file.Close()
	}
}

func (r *Reporter) clearProgressLocked() {
	if !r.wroteProgress {
		return
	}
	fmt.Fprint(os.Stderr, "\r\033[K")
	r.wroteProgress = false
}

func (r *Reporter) writeJSONLocked(v any) {
	if r.structBuf == nil {
		return
	}
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	if r.format == "json" {
		if !r.jsonFirst {
			_, _ = r.structBuf.WriteString(",\n")
		}
		r.jsonFirst = false
		_, _ = r.structBuf.Write(data)
		return
	}
	_, _ = r.structBuf.Write(data)
	_ = r.structBuf.WriteByte('\n')
}

func (r *Reporter) writeBucketCSVLocked(res BucketResult) {
	if r.csvOut == nil {
		return
	}
	var acl, aclWrite, policy, policyWrite, cors, website, configs string
	listed := strconv.Itoa(len(res.ListedObjects))
	objects := strconv.Itoa(len(res.Objects))
	if p := res.Permissions; p != nil {
		acl = boolString(p.ACLPublic)
		aclWrite = boolString(p.ACLPublicWrite)
		policy = boolString(p.PolicyPublic)
		policyWrite = boolString(p.PolicyPublicWrite)
		cors = boolString(p.CORSWildcard)
		website = boolString(p.WebsiteReadable)
		configs = strings.Join(p.AccessibleConfigs, ";")
	}
	row := []string{
		"bucket", res.Bucket, "", "", res.URL, res.Status,
		strconv.Itoa(res.HTTPStatus), res.Region, res.Provider,
		res.ErrorCode, res.Message, acl, aclWrite, policy, policyWrite, cors,
		website, listed, objects, configs,
	}
	_ = r.csvOut.Write(row)
}

func (r *Reporter) writeTakeoverCSVLocked(res TakeoverResult) {
	if r.csvOut == nil {
		return
	}
	row := []string{
		"takeover", res.Bucket, res.Domain, res.CNAME, res.URL, res.Status,
		strconv.Itoa(res.HTTPStatus), res.Region, res.Provider, "", res.Message,
		"", "", "", "", "", "", "", "", "",
	}
	_ = r.csvOut.Write(row)
}

func (r *Reporter) flushLocked() {
	if r.csvOut != nil {
		r.csvOut.Flush()
	}
	if r.structBuf != nil {
		_ = r.structBuf.Flush()
	}
	if r.consoleBuf != nil {
		_ = r.consoleBuf.Flush()
	}
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func bucketLine(res BucketResult, color bool) string {
	status := res.Status
	if color {
		status = paintStatus(status, res.Permissions)
	}
	line := res.URL
	if res.HTTPStatus != 0 {
		line += fmt.Sprintf(" [%d]", res.HTTPStatus)
	}
	line += fmt.Sprintf(" [%s]", status)
	if res.Region != "" {
		line += " [region=" + res.Region + "]"
	}
	if res.Message != "" {
		line += " " + res.Message
	}

	if p := res.Permissions; p != nil {
		var tags []string
		if p.ListBucket {
			tags = append(tags, "list")
		}
		if p.ACLPublicWrite || p.ACLPublicFullControl {
			tags = append(tags, "acl=PUBLIC-WRITE")
		} else if p.ACLPublic {
			tags = append(tags, "acl=public")
		} else if p.ACLReadable {
			tags = append(tags, "acl=read")
		}
		if p.PolicyPublicWrite {
			tags = append(tags, "policy=WRITE")
		} else if p.PolicyPublic {
			if p.PolicyConditional {
				tags = append(tags, "policy=public-cond")
			} else {
				tags = append(tags, "policy=public")
			}
		} else if p.PolicyReadable {
			tags = append(tags, "policy=read")
		}
		if p.CORSWildcard {
			tags = append(tags, "cors=*")
		} else if p.CORSReadable {
			tags = append(tags, "cors=read")
		}
		if p.WebsiteReadable {
			tags = append(tags, "website")
		}
		if p.PublicAccessBlockDisabled {
			tags = append(tags, "pab=disabled")
		}
		if p.LoggingEnabled {
			tags = append(tags, "logging")
		}
		if p.VersioningStatus != "" {
			tags = append(tags, "versioning="+strings.ToLower(p.VersioningStatus))
		}
		if len(tags) > 0 {
			line += " " + strings.Join(tags, " ")
		}
	}
	if len(res.ListedObjects) > 0 {
		line += fmt.Sprintf(" listed=%d", len(res.ListedObjects))
	}
	if len(res.Objects) > 0 {
		line += fmt.Sprintf(" objects=%d", len(res.Objects))
	}
	return line
}

func takeoverLine(res TakeoverResult, color bool) string {
	status := res.Status
	if color {
		switch res.Status {
		case TakeoverVulnerable:
			status = colorRed + colorBold + status + colorReset
		case TakeoverExists:
			status = colorYellow + status + colorReset
		case TakeoverError:
			status = colorRed + status + colorReset
		default:
			status = colorDim + status + colorReset
		}
	}
	line := fmt.Sprintf("[TAKEOVER] %s [%s]", describeTakeover(res), status)
	if res.HTTPStatus != 0 {
		line += fmt.Sprintf(" [%d]", res.HTTPStatus)
	}
	if res.Message != "" {
		line += " - " + res.Message
	}
	return line
}

func paintStatus(status string, perms *PermissionReport) string {
	if perms != nil && (perms.PolicyPublicWrite || perms.ACLPublicWrite || perms.ACLPublicFullControl) {
		return colorRed + colorBold + status + colorReset
	}
	switch status {
	case StatusPublic:
		return colorGreen + status + colorReset
	case StatusPrivate:
		return colorYellow + status + colorReset
	case StatusExists:
		return colorCyan + status + colorReset
	case StatusError:
		return colorRed + status + colorReset
	case StatusNotFound:
		return colorDim + status + colorReset
	default:
		return status
	}
}
