package main

import (
	"bufio"
	_ "embed"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

//go:embed common_bucket_prefixes.txt
var embeddedWordlist string

// ================= GLOBALS =================

var (
	verbose        bool
	useAWS         bool
	globalWordlist []string
)

var environments = []string{
	"dev", "development", "stage", "s3",
	"staging", "prod", "production", "test",
}

// ================= VERBOSE =================

func vprint(format string, a ...any) {
	if verbose {
		fmt.Printf(format+"\n", a...)
	}
}

// lightweight progress (non-verbose mode)
func progress(bucket string) {
	if !verbose {
		fmt.Printf("[+] Checking: %s\r", bucket)
	}
}

// ================= XML STRUCT =================

type ListBucketResult struct {
	Contents []struct {
		Size int64 `xml:"Size"`
	} `xml:"Contents"`
}

// ================= WORDLIST =================

func initWordlist(path string) error {
	var content string

	if path != "" {
		if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
			content = string(data)
			vprint("[VERBOSE] Using custom wordlist: %s", path)
		}
	}

	if content == "" {
		content = embeddedWordlist
		vprint("[VERBOSE] Using embedded wordlist")
	}

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			globalWordlist = append(globalWordlist, line)
		}
	}

	vprint("[VERBOSE] Loaded wordlist (%d entries)", len(globalWordlist))

	if len(globalWordlist) == 0 {
		return fmt.Errorf("wordlist empty")
	}
	return nil
}

// ================= S3 =================

type S3 struct {
	Bucket string
	URL    string
	Client *http.Client
}

func NewS3(bucket string) *S3 {
	return &S3{
		Bucket: bucket,
		URL:    fmt.Sprintf("http://%s.s3.amazonaws.com", bucket),
		Client: &http.Client{Timeout: 8 * time.Second},
	}
}

// ================= EXISTENCE =================

func (s *S3) Exists() (bool, int) {
	resp, err := s.Client.Get(s.URL)
	if err != nil {
		return false, 0
	}
	defer resp.Body.Close()

	code := resp.StatusCode

	// elite detection
	if code == 200 || code == 403 || code == 301 {
		return true, code
	}

	return false, code
}

// ================= REGION =================

func (s *S3) GetRegion() string {
	req, _ := http.NewRequest("HEAD", s.URL, nil)
	resp, err := s.Client.Do(req)
	if err != nil {
		return "us-east-1"
	}
	defer resp.Body.Close()

	r := resp.Header.Get("x-amz-bucket-region")
	if r == "" {
		return "us-east-1"
	}
	return r
}

// ================= ACL CHECK =================

func checkACL(bucket string) (authUsers, allUsers string) {
	authUsers = "[]"
	allUsers = "[]"

	if !useAWS {
		return
	}

	if _, err := exec.LookPath("aws"); err != nil {
		return
	}

	cmd := exec.Command(
		"aws", "s3api", "get-bucket-acl",
		"--bucket", bucket,
		"--no-sign-request",
	)

	out, err := cmd.Output()
	if err != nil {
		return
	}

	data := strings.ToLower(string(out))

	if strings.Contains(data, "allusers") {
		if strings.Contains(data, "read_acp") {
			allUsers = "[READ, READ_ACP]"
		} else if strings.Contains(data, "read") {
			allUsers = "[READ]"
		}
	}

	return
}

// ================= BUCKET STATS =================

func getBucketStats(bucket string) (int, int64) {
	url := fmt.Sprintf("http://%s.s3.amazonaws.com/?list-type=2", bucket)

	resp, err := http.Get(url)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return 0, 0
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var result ListBucketResult
	if err := xml.Unmarshal(body, &result); err != nil {
		return 0, 0
	}

	var total int64
	for _, obj := range result.Contents {
		total += obj.Size
	}

	return len(result.Contents), total
}

// ================= SIZE =================

func humanSize(bytes int64) string {
	if bytes <= 0 {
		return "0 B"
	}
	kb := float64(bytes) / 1024
	if kb < 1024 {
		return fmt.Sprintf("%.1f KB", kb)
	}
	mb := kb / 1024
	if mb < 1024 {
		return fmt.Sprintf("%.1f MB", mb)
	}
	gb := mb / 1024
	return fmt.Sprintf("%.2f GB", gb)
}

// ================= PERMUTATIONS =================

func generateWordlist(prefix string, words []string) []string {
	unique := make(map[string]bool)
	unique[prefix] = true

	for _, word := range words {
		for _, env := range environments {
			formats := []string{
				"%s-%s-%s",
				"%s-%s.%s",
				"%s-%s%s",
				"%s.%s-%s",
				"%s.%s.%s",
			}
			for _, f := range formats {
				unique[fmt.Sprintf(f, prefix, word, env)] = true
			}
		}
	}

	var result []string
	for k := range unique {
		result = append(result, k)
	}
	return result
}

// ================= OUTPUT =================

func writeLine(file *os.File, line string) {
	// clear progress line and print clean result
	fmt.Printf("\r%s\n", line)
	if file != nil {
		file.WriteString(line + "\n")
	}
}

// ================= SCAN =================

func scanBuckets(list []string, file *os.File) {
	vprint("[VERBOSE] Starting local scan (%d candidates)", len(list))

	if len(list) == 0 {
		fmt.Println("[WARN] zero candidates generated")
		return
	}

	seen := make(map[string]bool)

	for _, word := range list {
		if seen[word] {
			continue
		}
		seen[word] = true

		progress(word)

		s3 := NewS3(word)
		exists, code := s3.Exists()

		// always show result
		if !exists {
			line := fmt.Sprintf(
				"INFO %-10s | %s | status:%d",
				"not_exist",
				s3.URL,
				code,
			)
			writeLine(file, line)
			continue
		}

		region := s3.GetRegion()
		authUsers, allUsers := checkACL(word)
		count, size := getBucketStats(word)

		if count == 0 {
			line := fmt.Sprintf(
				"INFO %-10s | %s | %-10s | PRIVATE",
				"exists",
				s3.URL,
				region,
			)
			writeLine(file, line)
			continue
		}

		line := fmt.Sprintf(
			"INFO %-10s | %s | %-10s | AuthUsers:%s | AllUsers:%s | %d objects (%s)",
			"exists",
			s3.URL,
			region,
			authUsers,
			allUsers,
			count,
			humanSize(size),
		)

		writeLine(file, line)
	}
}

// ================= MAIN =================

func main() {
	target := flag.String("t", "", "Target (required)")
	wordlistFile := flag.String("w", "", "Wordlist")
	outputFile := flag.String("o", "", "Output file")
	flag.BoolVar(&verbose, "v", false, "Verbose mode")
	flag.BoolVar(&useAWS, "aws", false, "Use AWS CLI ACL check")
	flag.Parse()

	if *target == "" {
		fmt.Println("Usage: s3-checker -t <target>")
		os.Exit(1)
	}

	if err := initWordlist(*wordlistFile); err != nil {
		fmt.Println("Error:", err)
		return
	}

	wordlist := generateWordlist(*target, globalWordlist)
	vprint("[VERBOSE] Generated %d permutations", len(wordlist))

	var file *os.File
	var err error
	if *outputFile != "" {
		file, err = os.Create(*outputFile)
		if err != nil {
			fmt.Println("Output error:", err)
			return
		}
		defer file.Close()
	}

	scanBuckets(wordlist, file)
}
