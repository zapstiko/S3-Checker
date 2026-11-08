package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidBucketName(t *testing.T) {
	valid := []string{
		"abc",
		"my-bucket",
		"my.bucket",
		"a1b",
		"example-com-2024",
		strings.Repeat("a", 63),
	}
	for _, name := range valid {
		if !validBucketName(name) {
			t.Errorf("expected %q to be valid", name)
		}
	}

	invalid := []string{
		"ab",
		strings.Repeat("a", 64),
		"My-Bucket",
		"my_bucket",
		"-bucket",
		"bucket-",
		"bucket..name",
		"192.168.1.1",
		"xn--bucket",
		"bucket-s3alias",
		"bucket--ol-s3",
		"bucket.",
		".bucket",
		"bucket/name",
		"",
	}
	for _, name := range invalid {
		if validBucketName(name) {
			t.Errorf("expected %q to be invalid", name)
		}
	}
}

func TestTargetVariants(t *testing.T) {
	variants := targetVariants("https://www.Example.COM/path?q=1")
	for _, want := range []string{"www.example.com", "example.com", "example", "example-com", "examplecom"} {
		if !containsString(variants, want) {
			t.Errorf("targetVariants missing %q in %v", want, variants)
		}
	}
	for _, variant := range variants {
		if !validBucketName(variant) {
			t.Errorf("invalid variant generated: %q", variant)
		}
	}
	if got := targetVariants(""); got != nil {
		t.Errorf("expected nil for empty target, got %v", got)
	}
}

func TestGenerateTargetCandidates(t *testing.T) {
	words := []string{"backup", "data", "logs"}
	envs := []string{"dev", "prod", "staging", "qa", "uat"}

	candidates := normalizeCandidates(generateTargetCandidates("acme", words, envs, false))
	set := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		set[candidate] = struct{}{}
		if !validBucketName(candidate) {
			t.Fatalf("generated invalid candidate %q", candidate)
		}
	}

	for _, want := range []string{
		"acme", "acme-backup", "backup-acme", "acme-backup-prod",
		"acme-prod-backup", "acme-backup.prod", "acme-prod", "prod-acme",
		"acme.prod", "acme-data", "acme.logs",
	} {
		if _, ok := set[want]; !ok {
			t.Errorf("missing expected candidate %q", want)
		}
	}

	deep := normalizeCandidates(generateTargetCandidates("acme", words, envs, true))
	deepSet := make(map[string]struct{}, len(deep))
	for _, candidate := range deep {
		deepSet[candidate] = struct{}{}
	}
	for _, want := range []string{"acme-2024", "acme-1", "acme-us-east-1"} {
		if _, ok := deepSet[want]; !ok {
			t.Errorf("deep generation missing %q", want)
		}
	}

	dotted := normalizeCandidates(generateTargetCandidates("example.com", words, envs, false))
	dottedSet := make(map[string]struct{}, len(dotted))
	for _, candidate := range dotted {
		dottedSet[candidate] = struct{}{}
	}
	for _, want := range []string{"example", "example-com", "example.com", "example-backup", "example-com-backup"} {
		if _, ok := dottedSet[want]; !ok {
			t.Errorf("dotted target missing %q", want)
		}
	}
}

func TestProviderURLs(t *testing.T) {
	aws, err := resolveProvider("aws", "", "")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		bucket, region, want string
	}{
		{"my-bucket", "", "https://my-bucket.s3.amazonaws.com"},
		{"my.bucket", "", "https://s3.amazonaws.com/my.bucket"},
		{"my-bucket", "eu-west-1", "https://my-bucket.s3.eu-west-1.amazonaws.com"},
		{"my.bucket", "eu-west-1", "https://s3.eu-west-1.amazonaws.com/my.bucket"},
	}
	for _, tc := range tests {
		if got := aws.BucketURL(tc.bucket, tc.region); got != tc.want {
			t.Errorf("aws URL(%q, %q) = %q, want %q", tc.bucket, tc.region, got, tc.want)
		}
	}

	do, err := resolveProvider("digitalocean", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := do.BucketURL("my-bucket", ""), "https://nyc3.digitaloceanspaces.com/my-bucket"; got != want {
		t.Errorf("do URL = %q, want %q", got, want)
	}

	custom, err := resolveProvider("custom", "https://example.com/{bucket}", "")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := custom.BucketURL("my-bucket", ""), "https://example.com/my-bucket"; got != want {
		t.Errorf("custom URL = %q, want %q", got, want)
	}

	customRegion, err := resolveProvider("custom", "https://{region}.example.com/{bucket}", "eu-west-1")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := customRegion.BucketURL("my-bucket", ""), "https://eu-west-1.example.com/my-bucket"; got != want {
		t.Errorf("custom region URL = %q, want %q", got, want)
	}

	if _, err := resolveProvider("custom", "", ""); err == nil {
		t.Error("expected custom provider without endpoint to fail")
	}
	if _, err := resolveProvider("bogus", "", ""); err == nil {
		t.Error("expected unknown provider to fail")
	}
	if _, err := resolveProvider("custom", "https://{region}.example.com", ""); err == nil {
		t.Error("expected {region} endpoint without region to fail")
	}
}

func TestMatchS3CNAME(t *testing.T) {
	tests := []struct {
		host     string
		provider string
		bucket   string
		region   string
		match    bool
	}{
		{"my-bucket.s3.amazonaws.com", "aws", "my-bucket", "", true},
		{"my-bucket.s3.us-west-2.amazonaws.com", "aws", "my-bucket", "us-west-2", true},
		{"my-bucket.s3.dualstack.eu-west-1.amazonaws.com", "aws", "my-bucket", "eu-west-1", true},
		{"my-bucket.s3-website-us-east-1.amazonaws.com", "aws", "my-bucket", "us-east-1", true},
		{"my-bucket.s3-website.us-east-1.amazonaws.com", "aws", "my-bucket", "us-east-1", true},
		{"my-bucket.s3-accelerate.amazonaws.com", "aws", "my-bucket", "", true},
		{"my.bucket.s3.amazonaws.com", "aws", "my.bucket", "", true},
		{"*.my-bucket.s3.amazonaws.com", "aws", "my-bucket", "", true},
		{"my-bucket.nyc3.digitaloceanspaces.com", "do", "my-bucket", "nyc3", true},
		{"my-bucket.s3.us-east-1.wasabisys.com", "wasabi", "my-bucket", "us-east-1", true},
		{"my-bucket.s3.us-west-004.backblazeb2.com", "b2", "my-bucket", "us-west-004", true},
		{"my-bucket.us-east-1.linodeobjects.com", "linode", "my-bucket", "us-east-1", true},
		{"my-bucket.s3.fr-par.scw.cloud", "scaleway", "my-bucket", "fr-par", true},
		{"my-bucket.storage.googleapis.com", "gcs", "my-bucket", "", true},
		{"example.com", "", "", "", false},
		{"evil.s3.amazonaws.com.evil.com", "", "", "", false},
		{"ab.s3.amazonaws.com", "", "", "", false},
	}
	for _, tc := range tests {
		got := matchS3CNAME(tc.host)
		if !tc.match {
			if got != nil {
				t.Errorf("%s: expected no match, got %+v", tc.host, got)
			}
			continue
		}
		if got == nil {
			t.Errorf("%s: expected match", tc.host)
			continue
		}
		if got.provider.Name != tc.provider || got.bucket != tc.bucket || got.region != tc.region {
			t.Errorf("%s: got provider=%s bucket=%s region=%s", tc.host, got.provider.Name, got.bucket, got.region)
		}
	}
}

func TestParsePolicy(t *testing.T) {
	tests := []struct {
		name        string
		policy      string
		public      bool
		read        bool
		list        bool
		write       bool
		conditional bool
	}{
		{
			name:   "public read",
			policy: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`,
			public: true, read: true,
		},
		{
			name:   "public list and write",
			policy: `{"Statement":{"Effect":"Allow","Principal":{"AWS":"*"},"Action":["s3:ListBucket","s3:PutObject"]}}`,
			public: true, list: true, write: true,
		},
		{
			name:   "wildcard action",
			policy: `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:*"}]}`,
			public: true, read: true, list: true, write: true,
		},
		{
			name:   "conditional",
			policy: `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}`,
			public: true, read: true, conditional: true,
		},
		{
			name:   "deny only",
			policy: `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:GetObject"}]}`,
		},
		{
			name:   "non-public principal",
			policy: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"s3:GetObject"}]}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pr := &PermissionReport{}
			parsePolicy([]byte(tc.policy), pr)
			if pr.PolicyPublic != tc.public {
				t.Errorf("public = %v, want %v", pr.PolicyPublic, tc.public)
			}
			if pr.PolicyPublicRead != tc.read {
				t.Errorf("read = %v, want %v", pr.PolicyPublicRead, tc.read)
			}
			if pr.PolicyPublicList != tc.list {
				t.Errorf("list = %v, want %v", pr.PolicyPublicList, tc.list)
			}
			if pr.PolicyPublicWrite != tc.write {
				t.Errorf("write = %v, want %v", pr.PolicyPublicWrite, tc.write)
			}
			if pr.PolicyConditional != tc.conditional {
				t.Errorf("conditional = %v, want %v", pr.PolicyConditional, tc.conditional)
			}
		})
	}
}

func TestParseACL(t *testing.T) {
	publicACL := `<AccessControlPolicy><AccessControlList><Grant><Grantee><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee><Permission>READ</Permission></Grant></AccessControlList></AccessControlPolicy>`
	pr := &PermissionReport{}
	parseACL([]byte(publicACL), pr)
	if !pr.ACLPublic || !pr.ACLPublicRead || pr.ACLPublicWrite {
		t.Errorf("unexpected public-read ACL flags: %+v", pr)
	}

	writeACL := `<AccessControlPolicy><AccessControlList><Grant><Grantee><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee><Permission>WRITE</Permission></Grant></AccessControlList></AccessControlPolicy>`
	pr = &PermissionReport{}
	parseACL([]byte(writeACL), pr)
	if !pr.ACLPublic || !pr.ACLPublicWrite || pr.ACLPublicRead {
		t.Errorf("unexpected public-write ACL flags: %+v", pr)
	}

	fullACL := `<AccessControlPolicy><AccessControlList><Grant><Grantee><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>`
	pr = &PermissionReport{}
	parseACL([]byte(fullACL), pr)
	if !pr.ACLPublic || !pr.ACLPublicWrite || !pr.ACLPublicRead || !pr.ACLPublicFullControl {
		t.Errorf("unexpected full-control ACL flags: %+v", pr)
	}

	authACL := `<AccessControlPolicy><AccessControlList><Grant><Grantee><URI>http://acs.amazonaws.com/groups/global/AuthenticatedUsers</URI></Grantee><Permission>READ</Permission></Grant></AccessControlList></AccessControlPolicy>`
	pr = &PermissionReport{}
	parseACL([]byte(authACL), pr)
	if !pr.ACLAuthenticated || pr.ACLPublic {
		t.Errorf("unexpected ACL flags: public=%v auth=%v", pr.ACLPublic, pr.ACLAuthenticated)
	}

	ownerACL := `<AccessControlPolicy><AccessControlList><Grant><Grantee><ID>owner</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>`
	pr = &PermissionReport{}
	parseACL([]byte(ownerACL), pr)
	if pr.ACLPublic || pr.ACLAuthenticated {
		t.Error("owner-only ACL should not be public")
	}
}

func TestParsers(t *testing.T) {
	website := `<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix></IndexDocument><ErrorDocument><Key>error.html</Key></ErrorDocument></WebsiteConfiguration>`
	cfg := parseWebsite([]byte(website))
	if cfg == nil || cfg.IndexDocument != "index.html" || cfg.ErrorDocument != "error.html" {
		t.Errorf("unexpected website config: %+v", cfg)
	}

	if !parseCORS([]byte(`<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin></CORSRule></CORSConfiguration>`)) {
		t.Error("expected wildcard CORS")
	}
	if parseCORS([]byte(`<CORSConfiguration><CORSRule><AllowedOrigin>https://example.com</AllowedOrigin></CORSRule></CORSConfiguration>`)) {
		t.Error("did not expect wildcard CORS")
	}

	allBlocked := `<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>`
	if parsePublicAccessBlock([]byte(allBlocked)) {
		t.Error("all blocked configuration should not be reported as disabled")
	}
	notBlocked := `<PublicAccessBlockConfiguration><BlockPublicAcls>false</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>`
	if !parsePublicAccessBlock([]byte(notBlocked)) {
		t.Error("expected disabled public access block")
	}

	if got := parseS3ErrorCode([]byte(`<Error><Code>NoSuchBucket</Code></Error>`)); got != "NoSuchBucket" {
		t.Errorf("error code = %q", got)
	}
	if got := parseS3ErrorCode(nil); got != "" {
		t.Errorf("expected empty code, got %q", got)
	}
}

func TestRegionHelpers(t *testing.T) {
	if got := regionFromLocation("https://my-bucket.s3.eu-west-1.amazonaws.com/"); got != "eu-west-1" {
		t.Errorf("location region = %q", got)
	}
	if got := regionFromHost("my-bucket.s3.us-west-2.amazonaws.com"); got != "us-west-2" {
		t.Errorf("host region = %q", got)
	}
	if got := regionFromLocation(""); got != "" {
		t.Errorf("expected empty region, got %q", got)
	}
}

func TestEscapeKey(t *testing.T) {
	if got, want := escapeKey("dir/file name.txt"), "dir/file%20name.txt"; got != want {
		t.Errorf("escapeKey = %q, want %q", got, want)
	}
	if got, want := escapeKey(".env"), ".env"; got != want {
		t.Errorf("escapeKey = %q, want %q", got, want)
	}
}

func TestNormalizeCandidates(t *testing.T) {
	got := normalizeCandidates([]string{"My_Bucket", "ab", "good-name", "good-name", "192.168.1.1", "foo..bar"})
	want := []string{"my-bucket", "good-name"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("normalizeCandidates = %v, want %v", got, want)
	}
}

func TestLoadWordlist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(path, []byte("# comment\nFoo\nbar-baz\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	lines, err := loadWordlist(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(lines, ",") != "Foo,bar-baz" {
		t.Errorf("loadWordlist = %v", lines)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "alpha")
		fmt.Fprintln(w, "beta")
	}))
	defer server.Close()
	lines, err = loadWordlist(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(lines, ",") != "alpha,beta" {
		t.Errorf("remote wordlist = %v", lines)
	}

	htmlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, "<html></html>")
	}))
	defer htmlServer.Close()
	if _, err := loadWordlist(htmlServer.URL); err == nil {
		t.Error("expected HTML wordlist URL to fail")
	}
}

func TestCheckerPipeline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Amz-Bucket-Region", "eu-west-1")
		path := r.URL.Path
		if r.Method == http.MethodHead && path == "/test-bucket/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		switch {
		case strings.HasPrefix(r.URL.RawQuery, "list-type=2"):
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprint(w, `<ListBucketResult><Name>test-bucket</Name><Contents><Key>one.txt</Key><Size>1</Size><LastModified>2024-01-01T00:00:00.000Z</LastModified></Contents><Contents><Key>two.txt</Key><Size>2</Size><LastModified>2024-01-02T00:00:00.000Z</LastModified></Contents></ListBucketResult>`)
		case r.URL.RawQuery == "acl":
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprint(w, `<AccessControlPolicy><AccessControlList><Grant><Grantee><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee><Permission>READ</Permission></Grant></AccessControlList></AccessControlPolicy>`)
		case r.URL.RawQuery == "policy":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:PutObject"}]}`)
		case r.URL.RawQuery == "cors":
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprint(w, `<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin></CORSRule></CORSConfiguration>`)
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer server.Close()

	provider, err := resolveProvider("custom", server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	opts := &options{
		timeout:     2 * time.Second,
		retries:     0,
		concurrency: 2,
		objects:     2,
		objectKeys:  []string{"index.html"},
		userAgent:   "test",
		exclude:     map[int]struct{}{},
	}
	checker := NewChecker(opts)
	res := checker.CheckWith(context.Background(), provider, "", "test-bucket", true)

	if res.Status != StatusPublic || !res.Exists || res.HTTPStatus != http.StatusOK {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.Region != "eu-west-1" {
		t.Errorf("region = %q", res.Region)
	}
	if res.Permissions == nil {
		t.Fatal("expected permissions")
	}
	if !res.Permissions.ListBucket || len(res.ListedObjects) != 2 {
		t.Errorf("listing not detected: %+v", res.ListedObjects)
	}
	if !res.Permissions.ACLPublic || !res.Permissions.PolicyPublicWrite || !res.Permissions.CORSWildcard {
		t.Errorf("permission flags not detected: %+v", res.Permissions)
	}
	if len(res.Permissions.AccessibleConfigs) == 0 {
		t.Error("expected accessible configs")
	}
}

func TestOSINTKeyword(t *testing.T) {
	tests := map[string]string{
		"https://www.Example.com/path?q=1": "example",
		"acme-corp":                        "acme-corp",
		"my_brand.example":                 "my-brand",
		"a":                                "",
		"":                                 "",
		"foo%bar":                          "",
	}
	for input, want := range tests {
		if got := osintKeyword(input); got != want {
			t.Errorf("osintKeyword(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestCheckClassification(t *testing.T) {
	newChecker := func() *Checker {
		return NewChecker(&options{
			timeout:     time.Second,
			retries:     0,
			concurrency: 1,
			userAgent:   "test",
			exclude:     map[int]struct{}{},
		})
	}

	nonS3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer nonS3.Close()
	provider, _ := resolveProvider("custom", nonS3.URL, "")
	res := newChecker().CheckWith(context.Background(), provider, "", "bucket", false)
	if res.Status != StatusError {
		t.Errorf("non-S3 404 status = %s, want %s", res.Status, StatusError)
	}

	s3ish := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Amz-Request-Id", "abc")
		w.Header().Set("X-Amz-Error-Code", "NoSuchBucket")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer s3ish.Close()
	provider, _ = resolveProvider("custom", s3ish.URL, "")
	res = newChecker().CheckWith(context.Background(), provider, "", "bucket", false)
	if res.Status != StatusNotFound || res.Exists {
		t.Errorf("S3 404 status = %s exists=%v, want NOT_FOUND", res.Status, res.Exists)
	}
}

func TestReporterJSONAndCSV(t *testing.T) {
	result := BucketResult{
		Type:       "bucket",
		Bucket:     "test-bucket",
		URL:        "https://test-bucket.s3.amazonaws.com",
		Provider:   "aws",
		Status:     StatusPublic,
		Exists:     true,
		HTTPStatus: 200,
		Region:     "us-east-1",
		Permissions: &PermissionReport{
			ListBucket:        true,
			PolicyPublicWrite: true,
			AccessibleConfigs: []string{"list", "policy"},
		},
		CheckedAt: time.Now().UTC(),
	}

	jsonPath := filepath.Join(t.TempDir(), "results.json")
	opts := &options{
		format:     "json",
		output:     jsonPath,
		noColor:    true,
		noProgress: true,
		quiet:      true,
		exclude:    map[int]struct{}{},
	}
	reporter, err := newReporter(opts)
	if err != nil {
		t.Fatal(err)
	}
	reporter.ReportBucket(result)
	reporter.ReportTakeover(TakeoverResult{
		Type: "takeover", Domain: "sub.example.com", Status: TakeoverVulnerable,
		CheckedAt: time.Now().UTC(),
	})
	reporter.Close()

	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	var decoded []map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, data)
	}
	if len(decoded) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(decoded))
	}

	csvPath := filepath.Join(t.TempDir(), "results.csv")
	opts = &options{
		format:      "csv",
		output:      csvPath,
		noColor:     true,
		noProgress:  true,
		quiet:       true,
		takeoverAll: true,
		exclude:     map[int]struct{}{},
	}
	reporter, err = newReporter(opts)
	if err != nil {
		t.Fatal(err)
	}
	reporter.ReportBucket(result)
	reporter.ReportTakeover(TakeoverResult{
		Type: "takeover", Domain: "sub.example.com", Status: TakeoverExists,
		CheckedAt: time.Now().UTC(),
	})
	reporter.Close()

	f, err := os.Open(csvPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Fatalf("expected header + 2 rows, got %d", len(records))
	}
	for i, record := range records {
		if len(record) != len(csvHeader) {
			t.Errorf("record %d has %d columns, want %d", i, len(record), len(csvHeader))
		}
	}
}
