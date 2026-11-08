package main

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Provider describes an S3-compatible object storage service.
type Provider struct {
	Name          string
	PathStyle     bool
	DefaultRegion string
	// Endpoint is a URL template. {region} and {bucket} are substituted when present.
	Endpoint string
	// GlobalEndpoint is used when no region is supplied (AWS global endpoint).
	GlobalEndpoint string
}

// BucketURL returns the endpoint used to address a bucket.
// Dotted bucket names always use path-style addressing because the wildcard
// TLS certificate for *.s3.amazonaws.com does not cover multi-label names.
func (p Provider) BucketURL(bucket, region string) string {
	r := region
	if r == "" {
		r = p.DefaultRegion
	}
	ep := p.Endpoint
	if r == "" && p.GlobalEndpoint != "" {
		ep = p.GlobalEndpoint
	}
	ep = strings.ReplaceAll(ep, "{region}", r)
	ep = strings.TrimRight(ep, "/")

	if strings.Contains(ep, "{bucket}") {
		return strings.TrimRight(strings.ReplaceAll(ep, "{bucket}", bucket), "/")
	}
	if p.PathStyle || strings.Contains(bucket, ".") {
		return ep + "/" + bucket
	}

	u, err := url.Parse(ep)
	if err != nil || u.Host == "" {
		return ep + "/" + bucket
	}
	u.Host = bucket + "." + u.Host
	return strings.TrimRight(u.String(), "/")
}

// RootURL is BucketURL with a trailing slash, suitable for bucket-level requests.
func (p Provider) RootURL(bucket, region string) string {
	return p.BucketURL(bucket, region) + "/"
}

func resolveProvider(name, endpoint, region string) (Provider, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if endpoint != "" {
		ep := strings.TrimSpace(endpoint)
		if !strings.Contains(ep, "://") {
			ep = "https://" + ep
		}
		u, err := url.Parse(strings.ReplaceAll(strings.ReplaceAll(ep, "{region}", "region"), "{bucket}", "bucket"))
		if err != nil || u.Host == "" {
			return Provider{}, fmt.Errorf("invalid --endpoint %q", endpoint)
		}
		if strings.Contains(ep, "{region}") && region == "" {
			return Provider{}, fmt.Errorf("--endpoint uses {region} but --region is empty")
		}
		return Provider{Name: "custom", PathStyle: true, DefaultRegion: region, Endpoint: ep}, nil
	}

	switch name {
	case "", "aws", "s3", "amazon":
		return Provider{
			Name:           "aws",
			PathStyle:      false,
			Endpoint:       "https://s3.{region}.amazonaws.com",
			GlobalEndpoint: "https://s3.amazonaws.com",
		}, nil
	case "do", "digitalocean", "spaces":
		return Provider{
			Name:          "do",
			PathStyle:     true,
			DefaultRegion: "nyc3",
			Endpoint:      "https://{region}.digitaloceanspaces.com",
		}, nil
	case "wasabi":
		return Provider{
			Name:          "wasabi",
			PathStyle:     true,
			DefaultRegion: "us-east-1",
			Endpoint:      "https://s3.{region}.wasabisys.com",
		}, nil
	case "linode", "akamai":
		return Provider{
			Name:          "linode",
			PathStyle:     true,
			DefaultRegion: "us-east-1",
			Endpoint:      "https://{region}.linodeobjects.com",
		}, nil
	case "b2", "backblaze":
		return Provider{
			Name:          "b2",
			PathStyle:     true,
			DefaultRegion: "us-west-004",
			Endpoint:      "https://s3.{region}.backblazeb2.com",
		}, nil
	case "scaleway", "scw":
		return Provider{
			Name:          "scaleway",
			PathStyle:     true,
			DefaultRegion: "fr-par",
			Endpoint:      "https://s3.{region}.scw.cloud",
		}, nil
	case "gcs", "google", "gcp":
		return Provider{
			Name:      "gcs",
			PathStyle: true,
			Endpoint:  "https://storage.googleapis.com",
		}, nil
	case "custom":
		return Provider{}, fmt.Errorf("provider custom requires --endpoint")
	default:
		return Provider{}, fmt.Errorf("unknown provider %q (use aws, do, wasabi, linode, b2, scaleway, gcs, or custom)", name)
	}
}

var (
	awsRegionHeaderRe = regexp.MustCompile(`^s3[.-]([a-z0-9-]+)\.amazonaws\.com$`)
	awsVHostRe        = regexp.MustCompile(`^[a-z0-9.-]+\.s3[.-]([a-z0-9-]+)\.amazonaws\.com$`)
	awsLocationRe     = regexp.MustCompile(`s3[.-]([a-z0-9-]+)\.amazonaws\.com`)
)

// regionFromLocation extracts a region from a redirect Location header.
func regionFromLocation(location string) string {
	if location == "" {
		return ""
	}
	if u, err := url.Parse(location); err == nil && u.Host != "" {
		if m := awsLocationRe.FindStringSubmatch(strings.ToLower(u.Host)); len(m) == 2 {
			return m[1]
		}
	}
	if m := awsLocationRe.FindStringSubmatch(strings.ToLower(location)); len(m) == 2 {
		return m[1]
	}
	return ""
}

// regionFromHost extracts the region from an S3 endpoint hostname.
func regionFromHost(host string) string {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	for _, re := range []*regexp.Regexp{awsVHostRe, awsRegionHeaderRe} {
		if m := re.FindStringSubmatch(host); len(m) == 2 {
			return m[1]
		}
	}
	return ""
}
