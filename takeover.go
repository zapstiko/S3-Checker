package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	TakeoverVulnerable = "VULNERABLE"
	TakeoverExists     = "EXISTS"
	TakeoverNoS3       = "NO_S3"
	TakeoverError      = "ERROR"
)

type TakeoverResult struct {
	Type       string    `json:"type"`
	Domain     string    `json:"domain"`
	CNAME      string    `json:"cname,omitempty"`
	Provider   string    `json:"provider,omitempty"`
	Bucket     string    `json:"bucket,omitempty"`
	Region     string    `json:"region,omitempty"`
	Status     string    `json:"status"`
	HTTPStatus int       `json:"http_status,omitempty"`
	URL        string    `json:"url,omitempty"`
	Message    string    `json:"message,omitempty"`
	CheckedAt  time.Time `json:"checked_at"`
}

type cnameMatch struct {
	provider Provider
	bucket   string
	region   string
}

var (
	reAWSWebsite = regexp.MustCompile(`^(.+)\.s3-website[.-]([a-z0-9-]+)\.amazonaws\.com$`)
	reAWSAccel   = regexp.MustCompile(`^(.+)\.s3-accelerate(?:\.dualstack)?\.amazonaws\.com$`)
	reAWSDual    = regexp.MustCompile(`^(.+)\.s3\.dualstack\.([a-z0-9-]+)\.amazonaws\.com$`)
	reAWSRegion  = regexp.MustCompile(`^(.+)\.s3\.([a-z0-9-]+)\.amazonaws\.com$`)
	reAWSGlobal  = regexp.MustCompile(`^(.+)\.s3\.amazonaws\.com$`)
	reDO         = regexp.MustCompile(`^(.+)\.([a-z0-9-]+)\.digitaloceanspaces\.com$`)
	reWasabi     = regexp.MustCompile(`^(.+)\.s3\.([a-z0-9-]+)\.wasabisys\.com$`)
	reB2         = regexp.MustCompile(`^(.+)\.s3\.([a-z0-9-]+)\.backblazeb2\.com$`)
	reLinode     = regexp.MustCompile(`^(.+)\.([a-z0-9-]+)\.linodeobjects\.com$`)
	reScaleway   = regexp.MustCompile(`^(.+)\.s3\.([a-z0-9-]+)\.scw\.cloud$`)
	reGCS        = regexp.MustCompile(`^(.+)\.storage\.googleapis\.com$`)
	reDomain     = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
)

// matchS3CNAME recognizes CNAME targets used by S3 and S3-compatible providers.
func matchS3CNAME(host string) *cnameMatch {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return nil
	}

	build := func(providerName, bucket, region string) *cnameMatch {
		bucket = strings.TrimPrefix(bucket, "*.")
		bucket = strings.TrimSpace(bucket)
		if !validBucketName(bucket) {
			return nil
		}
		p, err := resolveProvider(providerName, "", region)
		if err != nil {
			return nil
		}
		return &cnameMatch{provider: p, bucket: bucket, region: region}
	}

	if m := reAWSWebsite.FindStringSubmatch(host); len(m) == 3 {
		return build("aws", m[1], m[2])
	}
	if m := reAWSAccel.FindStringSubmatch(host); len(m) == 2 {
		return build("aws", m[1], "")
	}
	if m := reAWSDual.FindStringSubmatch(host); len(m) == 3 {
		return build("aws", m[1], m[2])
	}
	if m := reAWSRegion.FindStringSubmatch(host); len(m) == 3 {
		return build("aws", m[1], m[2])
	}
	if m := reAWSGlobal.FindStringSubmatch(host); len(m) == 2 {
		return build("aws", m[1], "")
	}
	if m := reDO.FindStringSubmatch(host); len(m) == 3 {
		return build("do", m[1], m[2])
	}
	if m := reWasabi.FindStringSubmatch(host); len(m) == 3 {
		return build("wasabi", m[1], m[2])
	}
	if m := reB2.FindStringSubmatch(host); len(m) == 3 {
		return build("b2", m[1], m[2])
	}
	if m := reLinode.FindStringSubmatch(host); len(m) == 3 {
		return build("linode", m[1], m[2])
	}
	if m := reScaleway.FindStringSubmatch(host); len(m) == 3 {
		return build("scaleway", m[1], m[2])
	}
	if m := reGCS.FindStringSubmatch(host); len(m) == 2 {
		return build("gcs", m[1], "")
	}
	return nil
}

// DetectTakeover resolves a domain and identifies dangling S3 CNAMEs.
func (c *Checker) DetectTakeover(ctx context.Context, domain string) TakeoverResult {
	res := TakeoverResult{
		Type:      "takeover",
		Domain:    normalizeDomain(domain),
		Status:    TakeoverNoS3,
		CheckedAt: time.Now().UTC(),
	}
	if res.Domain == "" || !strings.Contains(res.Domain, ".") || !reDomain.MatchString(res.Domain) {
		res.Status = TakeoverError
		res.Message = "invalid domain name"
		return res
	}

	dnsCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	cname, err := net.DefaultResolver.LookupCNAME(dnsCtx, res.Domain)
	cancel()
	if err == nil {
		cname = strings.ToLower(strings.TrimSuffix(cname, "."))
		if cname != res.Domain {
			res.CNAME = cname
		}
		if match := matchS3CNAME(cname); match != nil {
			res.Provider = match.provider.Name
			res.Bucket = match.bucket
			res.Region = match.region
			res.URL = match.provider.BucketURL(match.bucket, match.region)

			br := c.CheckWith(ctx, match.provider, match.region, match.bucket, false)
			res.HTTPStatus = br.HTTPStatus
			if br.Region != "" {
				res.Region = br.Region
			}
			res.URL = br.URL
			switch br.Status {
			case StatusNotFound:
				res.Status = TakeoverVulnerable
				res.Message = "dangling CNAME: the S3 bucket name is unclaimed"
			case StatusPublic:
				res.Status = TakeoverExists
				res.Message = "bucket exists and is publicly listable; takeover not possible"
			case StatusPrivate, StatusExists:
				res.Status = TakeoverExists
				res.Message = "bucket exists; takeover not possible"
			default:
				res.Status = TakeoverError
				if br.Message != "" {
					res.Message = br.Message
				} else {
					res.Message = "could not verify bucket state"
				}
			}
			return res
		}
	}

	// Fallback for ALIAS/flattened records: inspect the HTTP response for
	// S3's NoSuchBucket signature.
	probe := c.probeDomainHTTP(ctx, res.Domain)
	res.HTTPStatus = probe.status
	if probe.vulnerable {
		res.Status = TakeoverVulnerable
		res.Message = "domain is served by S3 and the backing bucket is unclaimed (NoSuchBucket)"
		return res
	}
	if probe.s3 {
		res.Status = TakeoverExists
		res.Message = "domain is served by S3; no NoSuchBucket signature observed"
		return res
	}
	res.Status = TakeoverNoS3
	res.Message = "no S3 CNAME or S3 error signature found"
	return res
}

type domainProbe struct {
	status     int
	s3         bool
	vulnerable bool
}

func (c *Checker) probeDomainHTTP(ctx context.Context, host string) domainProbe {
	for _, scheme := range []string{"https", "http"} {
		if err := c.limiter.Wait(ctx); err != nil {
			return domainProbe{}
		}
		rawURL := scheme + "://" + host + "/"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", c.opts.userAgent)
		req.Header.Set("Accept", "*/*")

		resp, err := c.fallbackClient.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
		resp.Body.Close()
		text := string(body)
		lower := strings.ToLower(text)

		s3Backed := resp.Header.Get("X-Amz-Request-Id") != "" ||
			strings.Contains(strings.ToLower(resp.Header.Get("Server")), "amazons3") ||
			strings.Contains(lower, "<code>nosuchbucket</code>") ||
			strings.Contains(lower, "the specified bucket does not exist")

		if s3Backed && strings.Contains(lower, "nosuchbucket") {
			return domainProbe{status: resp.StatusCode, s3: true, vulnerable: true}
		}
		if s3Backed {
			return domainProbe{status: resp.StatusCode, s3: true}
		}
		if scheme == "https" && resp.StatusCode < 400 {
			return domainProbe{status: resp.StatusCode}
		}
	}
	return domainProbe{}
}

func normalizeDomain(input string) string {
	s := strings.TrimSpace(strings.ToLower(input))
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			s = u.Hostname()
		}
	}
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimSuffix(s, ".")
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// describeTakeover returns a short, grep-friendly description.
func describeTakeover(res TakeoverResult) string {
	if res.Bucket != "" {
		return fmt.Sprintf("%s -> %s (%s)", res.Domain, res.Bucket, res.Provider)
	}
	if res.CNAME != "" {
		return fmt.Sprintf("%s -> %s", res.Domain, res.CNAME)
	}
	return res.Domain
}
