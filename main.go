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
   AWS S3 Bucket Discovery & Permission Auditor
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
            github.com/zapstiko/s3-checker
            Abu Raihan Biswas (zapstiko)
`)
}

// ==================== LOGGING ====================

func vprint(format string, a ...any) {
	if verbose {
		fmt.Printf(format+"\n", a...)
	}
}

func normalCheck(bucket string) {
	if !verbose {
		fmt.Printf("[+] Checking %s\n", bucket)
	}
}

func verboseCheck(url string) {
	if verbose {
		fmt.Printf("[CHECK] %s\n", url)
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
		vprint("[VERBOSE] Using embedded wordlist (default)")
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
		Client: &http.Client{Timeout: 5 * time.Second},
	}
}

func (s *S3) Check() (int, string) {
	normalCheck(s.Bucket)
	verboseCheck(s.Domain)

	resp, err := s.Client.Get(s.Domain)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		return resp.StatusCode, "PUBLIC"
	case 403:
		return resp.StatusCode, "PRIVATE"
	default:
		return resp.StatusCode, ""
	}
}

// ==================== AWS PERMISSION CHECK ====================

func awsPermissionCheck(bucket string) string {
	if !useAWS {
		return ""
	}

	// ensure aws cli exists
	if _, err := exec.LookPath("aws"); err != nil {
		vprint("[VERBOSE] aws CLI not found — skipping AWS check")
		return ""
	}

	cmd := exec.Command(
		"aws", "s3", "ls",
		fmt.Sprintf("s3://%s", bucket),
		"--no-sign-request",
	)

	out, err := cmd.CombinedOutput()
	output := strings.ToLower(string(out))

	// publicly listable
	if err == nil {
		return "PUBLIC"
	}

	// exists but private
	if strings.Contains(output, "access denied") ||
		strings.Contains(output, "all access disabled") {
		return "PRIVATE"
	}

	return ""
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

	for _, word := range list {
		b := NewS3(word)
		code, perm := b.Check()

		// AWS verification overrides HTTP result
		awsPerm := awsPermissionCheck(b.Bucket)
		if awsPerm != "" {
			perm = awsPerm
		}

		if perm == "" {
			continue
		}

		url := fmt.Sprintf("http://%s.s3.amazonaws.com", b.Bucket)
		line := fmt.Sprintf("%s | %d | %s", url, code, perm)
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

	client := &http.Client{Timeout: 10 * time.Second}
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
		code, perm := b.Check()

		awsPerm := awsPermissionCheck(bucket)
		if awsPerm != "" {
			perm = awsPerm
		}

		if perm == "" {
			continue
		}

		url := fmt.Sprintf("http://%s.s3.amazonaws.com", bucket)
		line := fmt.Sprintf("%s | %d | %s", url, code, perm)
		writeLine(file, line)
	}
}

// ==================== OSINT ====================

func searchOSINT(keyword string, file *os.File) {
	vprint("[VERBOSE] Querying OSINT.sh…")

	url := fmt.Sprintf("https://osint.sh/buckets/?q=%s", keyword)

	client := &http.Client{Timeout: 10 * time.Second}
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
		code, perm := b.Check()

		awsPerm := awsPermissionCheck(bucket)
		if awsPerm != "" {
			perm = awsPerm
		}

		if perm == "" {
			continue
		}

		url := fmt.Sprintf("http://%s.s3.amazonaws.com", bucket)
		line := fmt.Sprintf("%s | %d | %s", url, code, perm)
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
