package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	StatusPublic   = "PUBLIC"
	StatusPrivate  = "PRIVATE"
	StatusExists   = "EXISTS"
	StatusNotFound = "NOT_FOUND"
	StatusError    = "ERROR"
)

type BucketResult struct {
	Type          string            `json:"type"`
	Bucket        string            `json:"bucket"`
	URL           string            `json:"url"`
	Provider      string            `json:"provider"`
	Status        string            `json:"status"`
	Exists        bool              `json:"exists"`
	HTTPStatus    int               `json:"http_status"`
	Region        string            `json:"region,omitempty"`
	ErrorCode     string            `json:"error_code,omitempty"`
	Message       string            `json:"message,omitempty"`
	Permissions   *PermissionReport `json:"permissions,omitempty"`
	Objects       []ObjectHit       `json:"objects,omitempty"`
	ListedObjects []ListedObject    `json:"listed_objects,omitempty"`
	CheckedAt     time.Time         `json:"checked_at"`
}

type ObjectHit struct {
	Key          string `json:"key"`
	Size         int64  `json:"size"`
	ContentType  string `json:"content_type,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
	URL          string `json:"url"`
}

type ListedObject struct {
	Key          string `json:"key"`
	Size         int64  `json:"size"`
	LastModified string `json:"last_modified,omitempty"`
}

type WebsiteConfig struct {
	IndexDocument    string `json:"index_document,omitempty"`
	ErrorDocument    string `json:"error_document,omitempty"`
	RedirectHost     string `json:"redirect_host,omitempty"`
	RedirectProtocol string `json:"redirect_protocol,omitempty"`
}

type PermissionReport struct {
	ListBucket                bool           `json:"list_bucket"`
	ACLReadable               bool           `json:"acl_readable"`
	ACLPublic                 bool           `json:"acl_public"`
	ACLPublicRead             bool           `json:"acl_public_read"`
	ACLPublicWrite            bool           `json:"acl_public_write"`
	ACLPublicFullControl      bool           `json:"acl_public_full_control"`
	ACLAuthenticated          bool           `json:"acl_authenticated"`
	PolicyReadable            bool           `json:"policy_readable"`
	PolicyPublic              bool           `json:"policy_public"`
	PolicyPublicRead          bool           `json:"policy_public_read"`
	PolicyPublicList          bool           `json:"policy_public_list"`
	PolicyPublicWrite         bool           `json:"policy_public_write"`
	PolicyConditional         bool           `json:"policy_conditional"`
	PolicyActions             []string       `json:"policy_actions,omitempty"`
	WebsiteReadable           bool           `json:"website_readable"`
	Website                   *WebsiteConfig `json:"website,omitempty"`
	CORSReadable              bool           `json:"cors_readable"`
	CORSWildcard              bool           `json:"cors_wildcard"`
	LoggingReadable           bool           `json:"logging_readable"`
	LoggingEnabled            bool           `json:"logging_enabled"`
	VersioningReadable        bool           `json:"versioning_readable"`
	VersioningStatus          string         `json:"versioning_status,omitempty"`
	TaggingReadable           bool           `json:"tagging_readable"`
	TagCount                  int            `json:"tag_count,omitempty"`
	EncryptionReadable        bool           `json:"encryption_readable"`
	LifecycleReadable         bool           `json:"lifecycle_readable"`
	LifecycleRules            int            `json:"lifecycle_rules,omitempty"`
	ReplicationReadable       bool           `json:"replication_readable"`
	ReplicationRules          int            `json:"replication_rules,omitempty"`
	PublicAccessBlockReadable bool           `json:"public_access_block_readable"`
	PublicAccessBlockDisabled bool           `json:"public_access_block_disabled"`
	ObjectLockReadable        bool           `json:"object_lock_readable"`
	NotificationReadable      bool           `json:"notification_readable"`
	UploadsReadable           bool           `json:"uploads_readable"`
	MultipartUploads          int            `json:"multipart_uploads,omitempty"`
	LocationReadable          bool           `json:"location_readable"`
	AccessibleConfigs         []string       `json:"accessible_configs,omitempty"`
}

func (p *PermissionReport) add(name string) {
	for _, existing := range p.AccessibleConfigs {
		if existing == name {
			return
		}
	}
	p.AccessibleConfigs = append(p.AccessibleConfigs, name)
}

func (p *PermissionReport) any() bool {
	return p != nil && (p.ListBucket || p.ACLReadable || p.PolicyReadable ||
		p.WebsiteReadable || p.CORSReadable || p.LoggingReadable ||
		p.VersioningReadable || p.TaggingReadable || p.EncryptionReadable ||
		p.LifecycleReadable || p.ReplicationReadable || p.PublicAccessBlockReadable ||
		p.ObjectLockReadable || p.NotificationReadable || p.UploadsReadable ||
		p.LocationReadable)
}

type Checker struct {
	client         *http.Client
	fallbackClient *http.Client
	limiter        *rateLimiter
	opts           *options
	provider       Provider
}

func NewChecker(opts *options) *Checker {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          opts.concurrency * 4,
		MaxIdleConnsPerHost:   opts.concurrency,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: opts.timeout,
		ExpectContinueTimeout: time.Second,
		ForceAttemptHTTP2:     true,
		DisableCompression:    true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	if opts.proxy != "" {
		if u, err := url.Parse(opts.proxy); err == nil && u.Host != "" {
			transport.Proxy = http.ProxyURL(u)
		}
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   opts.timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	fallback := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
	return &Checker{
		client:         client,
		fallbackClient: fallback,
		limiter:        newRateLimiter(opts.rate),
		opts:           opts,
		provider:       opts.prov,
	}
}

type rateLimiter struct {
	ch <-chan time.Time
}

func newRateLimiter(rate int) *rateLimiter {
	if rate <= 0 {
		return &rateLimiter{}
	}
	interval := time.Second / time.Duration(rate)
	if interval <= 0 {
		interval = time.Microsecond
	}
	ticker := time.NewTicker(interval)
	return &rateLimiter{ch: ticker.C}
}

func (l *rateLimiter) Wait(ctx context.Context) error {
	if l == nil || l.ch == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.ch:
		return nil
	}
}

type httpResult struct {
	status int
	header http.Header
	body   []byte
}

// Check scans a bucket using the configured provider.
func (c *Checker) Check(ctx context.Context, bucket string) BucketResult {
	return c.CheckWith(ctx, c.provider, c.opts.region, bucket, c.opts.perms)
}

// CheckWith scans a bucket using an explicit provider/region. It is also used
// by the takeover detector, which derives the provider from a CNAME.
func (c *Checker) CheckWith(ctx context.Context, p Provider, region, bucket string, perms bool) BucketResult {
	res := BucketResult{
		Type:      "bucket",
		Bucket:    bucket,
		Provider:  p.Name,
		CheckedAt: time.Now().UTC(),
	}
	base := p.BucketURL(bucket, region)
	res.URL = base

	hr, err := c.do(ctx, http.MethodHead, base+"/", 0)
	if err != nil {
		if ctx.Err() == nil {
			res.Status = StatusError
			res.Message = err.Error()
		}
		return res
	}
	// Some S3-compatible gateways do not implement HEAD on bucket roots.
	if hr.status == http.StatusMethodNotAllowed || hr.status == http.StatusNotImplemented {
		if hr2, err2 := c.do(ctx, http.MethodGet, base+"/", 1<<20); err2 == nil {
			hr = hr2
		}
	}

	c.classify(ctx, &res, p, region, hr)
	if res.Exists && perms {
		c.enumeratePermissions(ctx, &res, p, region)
	}
	return res
}

func (c *Checker) classify(ctx context.Context, res *BucketResult, p Provider, region string, hr *httpResult) {
	res.HTTPStatus = hr.status
	if r := strings.TrimSpace(hr.header.Get("X-Amz-Bucket-Region")); r != "" {
		res.Region = r
	}
	res.ErrorCode = parseS3ErrorCode(hr.body)
	if res.ErrorCode == "" {
		res.ErrorCode = strings.TrimSpace(hr.header.Get("X-Amz-Error-Code"))
	}
	if res.Message == "" && hr.status >= 400 {
		res.Message = strings.TrimSpace(hr.header.Get("X-Amz-Error-Message"))
	}

	switch {
	case hr.status >= 200 && hr.status < 300:
		res.Exists = true
		res.Status = StatusPublic
	case hr.status == http.StatusMovedPermanently || hr.status == http.StatusTemporaryRedirect || hr.status == http.StatusPermanentRedirect:
		res.Exists = true
		res.Status = StatusExists
		if res.Region == "" {
			res.Region = regionFromLocation(hr.header.Get("Location"))
		}
		if c.opts.followRegion && p.Name == "aws" && res.Region != "" {
			if hr2 := c.recheckRegional(ctx, res.Bucket, p, res.Region); hr2 != nil {
				res.HTTPStatus = hr2.status
				res.ErrorCode = parseS3ErrorCode(hr2.body)
				if hr2.status >= 200 && hr2.status < 300 {
					res.Status = StatusPublic
				} else if hr2.status == http.StatusForbidden {
					res.Status = StatusPrivate
				}
				res.URL = p.BucketURL(res.Bucket, res.Region)
			}
		}
	case hr.status == http.StatusForbidden:
		if strings.EqualFold(res.ErrorCode, "NoSuchBucket") {
			res.Status = StatusNotFound
		} else {
			res.Exists = true
			res.Status = StatusPrivate
		}
	case hr.status == http.StatusNotFound:
		if c.looksLikeS3(p, hr.header) {
			res.Status = StatusNotFound
			if res.ErrorCode == "" {
				res.ErrorCode = "NoSuchBucket"
			}
		} else {
			res.Status = StatusError
			res.Message = "404 from a non-S3 endpoint"
		}
	case hr.status == http.StatusBadRequest:
		res.Status = StatusError
		if res.ErrorCode == "" {
			res.Message = "bad request (invalid bucket name or endpoint)"
		}
	case hr.status == http.StatusTooManyRequests:
		res.Status = StatusError
		res.Message = "rate limited"
	default:
		res.Status = StatusError
		res.Message = fmt.Sprintf("unexpected HTTP %d", hr.status)
	}
}

func (c *Checker) recheckRegional(ctx context.Context, bucket string, p Provider, region string) *httpResult {
	base := p.BucketURL(bucket, region)
	hr, err := c.do(ctx, http.MethodHead, base+"/", 0)
	if err != nil {
		return nil
	}
	if hr.status == http.StatusMethodNotAllowed || hr.status == http.StatusNotImplemented {
		hr, err = c.do(ctx, http.MethodGet, base+"/", 1<<20)
		if err != nil {
			return nil
		}
	}
	if hr.status == http.StatusOK || hr.status == http.StatusForbidden {
		return hr
	}
	return nil
}

func (c *Checker) looksLikeS3(p Provider, h http.Header) bool {
	if h.Get("X-Amz-Request-Id") != "" || h.Get("X-Amz-Id-2") != "" || h.Get("X-Amz-Error-Code") != "" {
		return true
	}
	server := strings.ToLower(h.Get("Server"))
	if strings.Contains(server, "amazons3") || strings.Contains(server, "amazon simple storage") ||
		strings.Contains(server, "s3") || strings.Contains(server, "wasabi") ||
		strings.Contains(server, "minio") || strings.Contains(server, "google") {
		return true
	}
	if p.Name == "aws" {
		return false
	}
	contentType := strings.ToLower(h.Get("Content-Type"))
	return strings.Contains(contentType, "application/xml") || strings.Contains(contentType, "text/xml")
}

func (c *Checker) do(ctx context.Context, method, rawURL string, maxBody int64) (*httpResult, error) {
	attempts := c.opts.retries + 1
	var lastErr error

	for attempt := 0; attempt < attempts; attempt++ {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", c.opts.userAgent)
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Encoding", "identity")

		resp, err := c.client.Do(req)
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if attempt < attempts-1 {
				sleepCtx(ctx, backoffDelay(attempt))
				continue
			}
			return nil, err
		}

		var body []byte
		if method != http.MethodHead && maxBody > 0 {
			body, err = io.ReadAll(io.LimitReader(resp.Body, maxBody))
			if err != nil {
				lastErr = err
				resp.Body.Close()
				if attempt < attempts-1 {
					sleepCtx(ctx, backoffDelay(attempt))
					continue
				}
				return nil, err
			}
		} else {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		}
		resp.Body.Close()

		if isRetryableStatus(resp.StatusCode) && attempt < attempts-1 {
			delay := backoffDelay(attempt)
			if ra := parseRetryAfter(resp.Header.Get("Retry-After")); ra > 0 && ra < 10*time.Second {
				delay = ra
			}
			sleepCtx(ctx, delay)
			continue
		}
		return &httpResult{status: resp.StatusCode, header: resp.Header, body: body}, nil
	}
	return nil, lastErr
}

func isRetryableStatus(code int) bool {
	switch code {
	case http.StatusRequestTimeout, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func backoffDelay(attempt int) time.Duration {
	if attempt > 4 {
		attempt = 4
	}
	base := 250 * time.Millisecond * time.Duration(1<<uint(attempt))
	jitter := time.Duration(rand.IntN(250)) * time.Millisecond
	return base + jitter
}

func sleepCtx(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func parseRetryAfter(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second
	}
	if t, err := http.ParseTime(value); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

type s3ErrorXML struct {
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

func parseS3ErrorCode(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var e s3ErrorXML
	if err := xml.Unmarshal(body, &e); err != nil {
		return ""
	}
	return strings.TrimSpace(e.Code)
}

func pickRegion(primary, fallback string) string {
	if primary != "" {
		return primary
	}
	return fallback
}

// ================= PERMISSION / EXPOSURE ENUMERATION =================

func (c *Checker) enumeratePermissions(ctx context.Context, res *BucketResult, p Provider, region string) {
	base := p.BucketURL(res.Bucket, pickRegion(res.Region, region))
	pr := &PermissionReport{ListBucket: res.Status == StatusPublic}
	if pr.ListBucket {
		pr.add("list")
	}
	maxKeys := c.opts.objects

	if res.Region == "" {
		if hr, err := c.do(ctx, http.MethodGet, base+"/?location", 1<<20); err == nil && hr.status == http.StatusOK {
			pr.LocationReadable = true
			pr.add("location")
			var loc struct {
				Value string `xml:",chardata"`
			}
			if xml.Unmarshal(hr.body, &loc) == nil {
				if v := strings.TrimSpace(loc.Value); v != "" {
					res.Region = v
				} else if p.Name == "aws" {
					res.Region = "us-east-1"
				}
			}
		}
	}

	if maxKeys > 0 {
		if listing, ok := c.listObjects(ctx, base, maxKeys); ok {
			pr.ListBucket = true
			pr.add("list")
			res.ListedObjects = listing
			if len(res.ListedObjects) > 0 && res.Status != StatusPublic {
				res.Status = StatusPublic
			}
		}
	}

	configs := []struct {
		name  string
		query string
	}{
		{"acl", "acl"},
		{"policy", "policy"},
		{"website", "website"},
		{"cors", "cors"},
		{"logging", "logging"},
		{"versioning", "versioning"},
		{"tagging", "tagging"},
		{"encryption", "encryption"},
		{"lifecycle", "lifecycle"},
		{"replication", "replication"},
		{"publicAccessBlock", "publicAccessBlock"},
		{"object-lock", "object-lock"},
		{"notification", "notification"},
		{"uploads", "uploads"},
	}
	for _, cfg := range configs {
		hr, err := c.do(ctx, http.MethodGet, base+"/?"+cfg.query, 4<<20)
		if err != nil || hr.status != http.StatusOK {
			continue
		}
		switch cfg.name {
		case "acl":
			pr.ACLReadable = true
			parseACL(hr.body, pr)
		case "policy":
			pr.PolicyReadable = true
			parsePolicy(hr.body, pr)
		case "website":
			pr.WebsiteReadable = true
			pr.Website = parseWebsite(hr.body)
		case "cors":
			pr.CORSReadable = true
			pr.CORSWildcard = parseCORS(hr.body)
		case "logging":
			pr.LoggingReadable = true
			pr.LoggingEnabled = parseLogging(hr.body)
		case "versioning":
			pr.VersioningReadable = true
			pr.VersioningStatus = parseVersioning(hr.body)
		case "tagging":
			pr.TaggingReadable = true
			pr.TagCount = parseTagCount(hr.body)
		case "encryption":
			pr.EncryptionReadable = true
		case "lifecycle":
			pr.LifecycleReadable = true
			pr.LifecycleRules = parseRuleCount(hr.body)
		case "replication":
			pr.ReplicationReadable = true
			pr.ReplicationRules = parseRuleCount(hr.body)
		case "publicAccessBlock":
			pr.PublicAccessBlockReadable = true
			pr.PublicAccessBlockDisabled = parsePublicAccessBlock(hr.body)
		case "object-lock":
			pr.ObjectLockReadable = true
		case "notification":
			pr.NotificationReadable = true
		case "uploads":
			pr.UploadsReadable = true
			pr.MultipartUploads = parseUploadCount(hr.body)
		}
		pr.add(cfg.name)
	}

	// If ListBucket is denied, probe well-known object keys instead.
	if !pr.ListBucket && maxKeys > 0 {
		keys := c.opts.objectKeys
		if len(keys) > maxKeys {
			keys = keys[:maxKeys]
		}
		for _, key := range keys {
			objectURL := base + "/" + escapeKey(key)
			hr, err := c.do(ctx, http.MethodHead, objectURL, 0)
			if err != nil || hr.status != http.StatusOK {
				continue
			}
			size := int64(-1)
			if cl := hr.header.Get("Content-Length"); cl != "" {
				if n, err := strconv.ParseInt(cl, 10, 64); err == nil {
					size = n
				}
			}
			res.Objects = append(res.Objects, ObjectHit{
				Key:          key,
				Size:         size,
				ContentType:  hr.header.Get("Content-Type"),
				LastModified: hr.header.Get("Last-Modified"),
				URL:          objectURL,
			})
		}
	}

	sort.Strings(pr.AccessibleConfigs)
	if pr.any() || len(res.Objects) > 0 {
		res.Permissions = pr
	}
}

func (c *Checker) listObjects(ctx context.Context, base string, maxKeys int) ([]ListedObject, bool) {
	if maxKeys <= 0 {
		maxKeys = 10
	}
	rawURL := base + "/?list-type=2&max-keys=" + strconv.Itoa(maxKeys)
	hr, err := c.do(ctx, http.MethodGet, rawURL, 16<<20)
	if err != nil || hr.status != http.StatusOK {
		return nil, false
	}
	var result struct {
		Contents []struct {
			Key          string `xml:"Key"`
			Size         int64  `xml:"Size"`
			LastModified string `xml:"LastModified"`
		} `xml:"Contents"`
		CommonPrefixes []struct {
			Prefix string `xml:"Prefix"`
		} `xml:"CommonPrefixes"`
	}
	if err := xml.Unmarshal(hr.body, &result); err != nil {
		return nil, false
	}
	out := make([]ListedObject, 0, len(result.Contents)+len(result.CommonPrefixes))
	for _, item := range result.Contents {
		out = append(out, ListedObject{Key: item.Key, Size: item.Size, LastModified: item.LastModified})
		if len(out) >= maxKeys {
			break
		}
	}
	for _, prefix := range result.CommonPrefixes {
		if len(out) >= maxKeys {
			break
		}
		out = append(out, ListedObject{Key: prefix.Prefix})
	}
	return out, true
}

func escapeKey(key string) string {
	parts := strings.Split(key, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}

// ================= XML / JSON PARSERS =================

func parseACL(body []byte, pr *PermissionReport) {
	var acl struct {
		Grants []struct {
			Grantee struct {
				URI string `xml:"URI"`
			} `xml:"Grantee"`
			Permission string `xml:"Permission"`
		} `xml:"AccessControlList>Grant"`
	}
	if xml.Unmarshal(body, &acl) != nil {
		return
	}
	for _, grant := range acl.Grants {
		uri := strings.ToLower(grant.Grantee.URI)
		permission := strings.ToUpper(strings.TrimSpace(grant.Permission))
		switch {
		case strings.Contains(uri, "global/allusers"):
			pr.ACLPublic = true
			if permission == "READ" || permission == "FULL_CONTROL" {
				pr.ACLPublicRead = true
			}
			if permission == "WRITE" || permission == "FULL_CONTROL" {
				pr.ACLPublicWrite = true
			}
			if permission == "FULL_CONTROL" {
				pr.ACLPublicFullControl = true
			}
		case strings.Contains(uri, "global/authenticatedusers"):
			pr.ACLAuthenticated = true
		}
	}
}

func parsePolicy(body []byte, pr *PermissionReport) {
	var doc struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if json.Unmarshal(body, &doc) != nil || len(doc.Statement) == 0 {
		return
	}

	var statements []json.RawMessage
	if doc.Statement[0] == '[' {
		if json.Unmarshal(doc.Statement, &statements) != nil {
			return
		}
	} else {
		statements = []json.RawMessage{doc.Statement}
	}

	actions := make(map[string]struct{})
	conditional := false
	for _, raw := range statements {
		var statement struct {
			Effect    string          `json:"Effect"`
			Principal json.RawMessage `json:"Principal"`
			Action    json.RawMessage `json:"Action"`
			Condition json.RawMessage `json:"Condition"`
		}
		if json.Unmarshal(raw, &statement) != nil {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(statement.Effect), "Allow") {
			continue
		}
		if !principalIsPublic(statement.Principal) {
			continue
		}
		list := normalizeStringList(statement.Action)
		if len(list) == 0 {
			continue
		}
		if cond := strings.TrimSpace(string(statement.Condition)); cond != "" && cond != "null" && cond != "{}" {
			conditional = true
		}
		for _, action := range list {
			actions[strings.ToLower(action)] = struct{}{}
		}
	}
	if len(actions) == 0 {
		return
	}

	pr.PolicyPublic = true
	pr.PolicyConditional = conditional
	for action := range actions {
		pr.PolicyActions = append(pr.PolicyActions, action)
		if actionMatches(action, "s3:getobject") {
			pr.PolicyPublicRead = true
		}
		if actionMatches(action, "s3:listbucket") {
			pr.PolicyPublicList = true
		}
		if actionMatches(action, "s3:putobject") || actionMatches(action, "s3:deleteobject") {
			pr.PolicyPublicWrite = true
		}
	}
	sort.Strings(pr.PolicyActions)
}

func principalIsPublic(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return false
	}
	var isStar func(any) bool
	isStar = func(v any) bool {
		switch x := v.(type) {
		case string:
			return strings.TrimSpace(x) == "*"
		case []any:
			for _, item := range x {
				if isStar(item) {
					return true
				}
			}
		case map[string]any:
			for key, item := range x {
				if strings.EqualFold(key, "AWS") && isStar(item) {
					return true
				}
			}
		}
		return false
	}
	return isStar(value)
}

func normalizeStringList(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return nil
	}
	var out []string
	switch x := value.(type) {
	case string:
		out = append(out, x)
	case []any:
		for _, item := range x {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func actionMatches(action, target string) bool {
	action = strings.ToLower(strings.TrimSpace(action))
	if action == "*" || action == "s3:*" || action == target {
		return true
	}
	if strings.HasSuffix(action, "*") {
		return strings.HasPrefix(target, strings.TrimSuffix(action, "*"))
	}
	return false
}

func parseWebsite(body []byte) *WebsiteConfig {
	var website struct {
		IndexDocument struct {
			Suffix string `xml:"Suffix"`
		} `xml:"IndexDocument"`
		ErrorDocument struct {
			Key string `xml:"Key"`
		} `xml:"ErrorDocument"`
		RedirectAllRequestsTo struct {
			HostName string `xml:"HostName"`
			Protocol string `xml:"Protocol"`
		} `xml:"RedirectAllRequestsTo"`
	}
	if xml.Unmarshal(body, &website) != nil {
		return nil
	}
	out := &WebsiteConfig{
		IndexDocument:    website.IndexDocument.Suffix,
		ErrorDocument:    website.ErrorDocument.Key,
		RedirectHost:     website.RedirectAllRequestsTo.HostName,
		RedirectProtocol: website.RedirectAllRequestsTo.Protocol,
	}
	if out.IndexDocument == "" && out.ErrorDocument == "" && out.RedirectHost == "" {
		return nil
	}
	return out
}

func parseCORS(body []byte) bool {
	var cors struct {
		Rules []struct {
			AllowedOrigins []string `xml:"AllowedOrigin"`
		} `xml:"CORSRule"`
	}
	if xml.Unmarshal(body, &cors) != nil {
		return false
	}
	for _, rule := range cors.Rules {
		for _, origin := range rule.AllowedOrigins {
			if strings.TrimSpace(origin) == "*" {
				return true
			}
		}
	}
	return false
}

func parseLogging(body []byte) bool {
	var logging struct {
		Enabled *struct {
			TargetBucket string `xml:"TargetBucket"`
		} `xml:"LoggingEnabled"`
	}
	if xml.Unmarshal(body, &logging) != nil {
		return false
	}
	return logging.Enabled != nil
}

func parseVersioning(body []byte) string {
	var versioning struct {
		Status string `xml:"Status"`
	}
	if xml.Unmarshal(body, &versioning) != nil {
		return ""
	}
	return versioning.Status
}

func parseTagCount(body []byte) int {
	var tagging struct {
		TagSet []struct {
			Key string `xml:"Key"`
		} `xml:"TagSet>Tag"`
	}
	if xml.Unmarshal(body, &tagging) != nil {
		return 0
	}
	return len(tagging.TagSet)
}

func parseRuleCount(body []byte) int {
	var rules struct {
		Rules []struct {
			ID string `xml:"ID"`
		} `xml:"Rule"`
	}
	if xml.Unmarshal(body, &rules) != nil {
		return 0
	}
	return len(rules.Rules)
}

func parsePublicAccessBlock(body []byte) bool {
	var block struct {
		BlockPublicAcls       bool `xml:"BlockPublicAcls"`
		IgnorePublicAcls      bool `xml:"IgnorePublicAcls"`
		BlockPublicPolicy     bool `xml:"BlockPublicPolicy"`
		RestrictPublicBuckets bool `xml:"RestrictPublicBuckets"`
	}
	if xml.Unmarshal(body, &block) != nil {
		return false
	}
	return !(block.BlockPublicAcls && block.IgnorePublicAcls && block.BlockPublicPolicy && block.RestrictPublicBuckets)
}

func parseUploadCount(body []byte) int {
	var uploads struct {
		Items []struct {
			Key string `xml:"Key"`
		} `xml:"Upload"`
	}
	if xml.Unmarshal(body, &uploads) != nil {
		return 0
	}
	return len(uploads.Items)
}
