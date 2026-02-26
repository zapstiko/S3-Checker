package main

import (
	"bufio"
	_ "embed"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

/*
   s3-checker
   Valid-bucket aware + clean single output
   Developed by Abu Raihan Biswas (zapstiko)
*/

// ==================== EMBED ====================

//go:embed common_bucket_prefixes.txt
var embeddedWordlist string

// ==================== GLOBALS ====================

var environments = []string{
	"dev", "development", "stage", "s3",
	"staging", "prod", "production", "test",
}

var (
	verbose        bool
	useAWS         bool
	globalWordlist []string
)

// ==================== BANNER ====================

func banner() {
	fmt.Println(`
   ____   _____      _____ _               _
  / ___| |___ /     / ____| |__   ___  ___| | _____ _ __
  \___ \   |_ \____| |    | '_ \ / _ \/ __| |/ / _ \ '__|
   ___) | ___) |____| |___ | | | |  __/ (__|   <  __/ |
  |____/ |____/      \____||_| |_|\___|\___|_|\_\___|_|

            s3-checker — S3 Bucket Discovery Tool
`)
}

// ==================== VERBOSE ====================

func vprint(format string, a ...any) {
	if verbose {
		fmt.Printf(format+"\n", a...)
	}
}

func logCheck(bucket, url string) {
	if verbose {
		fmt.Printf("[CHECK] %s (%s)\n", bucket, url)
	}
}

// ==================== WORDLIST INIT ====================

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

	if len(globalWordlist) == 0 {
		return fmt.Errorf("wordlist is empty")
	}

	vprint("[VERBOSE] Loaded wordlist (%d entries)", len(globalWordlist))
	return nil
}

// ==================== S3 CHECKER ====================

type S3 struct {
	Bucket string
	Domain string
	Client *http.Client
}

func NewS3(bucket string) *S3 {
	return &S3{
		Bucket: bucket,
		Domain: fmt.Sprintf("http://%s.s3.amazonaws.com", bucket),
		Client: &http.Client{Timeout: 6 * time.Second},
	}
}

// -------- VALID BUCKET DETECTOR (NEW) --------

func (s *S3) Exists() (bool, int) {
	logCheck(s.Bucket, s.Domain)

	resp, err := s.Client.Get(s.Domain)
	if err != nil {
		return false, 0
	}
	defer resp.Body.Close()

	code := resp.StatusCode

	// VALID bucket indicators
	switch code {
	case 200, 403:
		return true, code
	case 404:
		return false, code
	default:
		return false, code
	}
}

// ==================== FINAL PERMISSION CLASSIFIER ====================

func classifyPermissions(bucket string) string {
	httpPublic := false
	awsPublic := false

	// HTTP list check
	httpURL := fmt.Sprintf("http://%s.s3.amazonaws.com/?list-type=2", bucket)
	resp, err := http.Get(httpURL)
	if err == nil && resp.StatusCode == 200 {
		httpPublic = true
	}
	if resp != nil {
		resp.Body.Close()
	}

	// AWS CLI check
	if useAWS {
		if _, err := exec.LookPath("aws"); err == nil {
			cmd := exec.Command(
				"aws", "s3", "ls",
				fmt.Sprintf("s3://%s", bucket),
				"--no-sign-request",
			)
			if err := cmd.Run(); err == nil {
				awsPublic = true
			}
		}
	}

	if httpPublic || awsPublic {
		return "PUBLIC"
	}
	return "PRIVATE"
}

// ==================== PERMUTATIONS ====================

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

	for _, word := range words {
		formats := []string{"%s.%s", "%s-%s", "%s%s"}
		for _, f := range formats {
			unique[fmt.Sprintf(f, prefix, word)] = true
			unique[fmt.Sprintf(f, word, prefix)] = true
		}
	}

	var result []string
	for k := range unique {
		result = append(result, k)
	}
	return result
}

// ==================== OUTPUT ====================

func writeLine(file *os.File, line string) {
	fmt.Println(line)
	if file != nil {
		file.WriteString(line + "\n")
	}
}

// ==================== LOCAL SCAN ====================

func scanBuckets(list []string, file *os.File) {
	vprint("[VERBOSE] Starting local scan (%d candidates)", len(list))

	seen := make(map[string]bool)

	for _, word := range list {
		if seen[word] {
			continue
		}
		seen[word] = true

		b := NewS3(word)

		// ✅ NEW: strict existence check
		exists, code := b.Exists()
		if !exists {
			continue
		}

		finalPerm := classifyPermissions(b.Bucket)

		url := fmt.Sprintf("http://%s.s3.amazonaws.com", b.Bucket)
		line := fmt.Sprintf("%s | %d | %s", url, code, finalPerm)
		writeLine(file, line)
	}
}

// ==================== GRAYHAT ====================

func searchGrayHat(keyword string, file *os.File) {
	apiKey := os.Getenv("GHW_API_KEY")
	if apiKey == "" {
		return
	}

	vprint("[VERBOSE] Querying GrayHatWarfare…")

	url := fmt.Sprintf(
		"https://buckets.grayhatwarfare.com/api/v1/buckets?keywords=%s",
		keyword,
	)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}

	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: 12 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	re := regexp.MustCompile(`"bucket"\s*:\s*"([^"]+)"`)
	matches := re.FindAllStringSubmatch(string(body), -1)

	seen := make(map[string]bool)

	for _, m := range matches {
		bucket := m[1]
		if seen[bucket] {
			continue
		}
		seen[bucket] = true

		b := NewS3(bucket)
		exists, code := b.Exists()
		if !exists {
			continue
		}

		finalPerm := classifyPermissions(bucket)

		url := fmt.Sprintf("http://%s.s3.amazonaws.com", bucket)
		line := fmt.Sprintf("%s | %d | %s", url, code, finalPerm)
		writeLine(file, line)
	}
}

// ==================== OSINT ====================

func searchOSINT(keyword string, file *os.File) {
	vprint("[VERBOSE] Querying OSINT.sh…")

	url := fmt.Sprintf("https://osint.sh/buckets/?q=%s", keyword)

	client := &http.Client{Timeout: 12 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	re := regexp.MustCompile(`([a-z0-9\.-]+)\.s3\.amazonaws\.com`)
	matches := re.FindAllStringSubmatch(string(body), -1)

	seen := make(map[string]bool)

	for _, m := range matches {
		bucket := m[1]
		if seen[bucket] {
			continue
		}
		seen[bucket] = true

		b := NewS3(bucket)
		exists, code := b.Exists()
		if !exists {
			continue
		}

		finalPerm := classifyPermissions(bucket)

		url := fmt.Sprintf("http://%s.s3.amazonaws.com", bucket)
		line := fmt.Sprintf("%s | %d | %s", url, code, finalPerm)
		writeLine(file, line)
	}
}

// ==================== MAIN ====================

func main() {
	target := flag.String("t", "", "Target name (required)")
	wordlistFile := flag.String("w", "", "Wordlist file")
	outputFile := flag.String("o", "", "Output file")
	flag.BoolVar(&verbose, "v", false, "Verbose mode")
	flag.BoolVar(&useAWS, "aws", false, "Verify permissions using AWS CLI")
	flag.Parse()

	banner()

	if *target == "" {
		fmt.Println("Usage: s3-checker -t <target>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if err := initWordlist(*wordlistFile); err != nil {
		fmt.Println("Error loading wordlist:", err)
		return
	}

	wordlist := generateWordlist(*target, globalWordlist)
	vprint("[VERBOSE] Generated %d permutations", len(wordlist))

	var file *os.File
	var err error
	if *outputFile != "" {
		file, err = os.Create(*outputFile)
		if err != nil {
			fmt.Println("Error creating output file:", err)
			return
		}
		defer file.Close()
	}

	scanBuckets(wordlist, file)
	searchGrayHat(*target, file)
	searchOSINT(*target, file)
}
