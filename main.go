package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

/*
            s3-checker — S3 Bucket Discovery Tool
            github.com/zapstiko/s3-checker
            Abu Raihan Biswas (zapstiko)
*/

var environments = []string{
	"dev", "development", "stage", "s3",
	"staging", "prod", "production", "test",
}

var verbose bool

// --------------------
// Banner
// --------------------
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

// --------------------
// Verbose logger
// --------------------
func vprint(format string, a ...any) {
	if verbose {
		fmt.Printf(format+"\n", a...)
	}
}

// --------------------
// S3 checker
// --------------------
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
	vprint("[VERBOSE] Checking %s", s.Domain)

	resp, err := s.Client.Get(s.Domain)
	if err != nil {
		vprint("[VERBOSE] Error: %v", err)
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

// --------------------
// Wordlist generator
// --------------------
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

// --------------------
// Read wordlist
// --------------------
func readWordlist(file string) ([]string, error) {
	vprint("[VERBOSE] Loading wordlist: %s", file)

	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var words []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			words = append(words, line)
		}
	}
	return words, nil
}

// --------------------
// Output helper
// --------------------
func writeLine(file *os.File, line string) {
	fmt.Println(line)
	if file != nil {
		file.WriteString(line + "\n")
	}
}

// --------------------
// Local scan
// --------------------
func scanBuckets(list []string, file *os.File) {
	vprint("[VERBOSE] Starting local permutation scan (%d candidates)", len(list))

	for _, word := range list {
		b := NewS3(word)
		code, perm := b.Check()
		if perm == "" {
			continue
		}

		url := fmt.Sprintf("http://%s.s3.amazonaws.com", b.Bucket)
		line := fmt.Sprintf("%s | %d | %s", url, code, perm)
		writeLine(file, line)
	}
}

// --------------------
// GrayHat search
// --------------------
func searchGrayHat(keyword string, file *os.File) {
	apiKey := os.Getenv("GHW_API_KEY")
	if apiKey == "" {
		vprint("[VERBOSE] GrayHat skipped (no API key)")
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
		if perm == "" {
			continue
		}

		url := fmt.Sprintf("http://%s.s3.amazonaws.com", bucket)
		line := fmt.Sprintf("%s | %d | %s", url, code, perm)
		writeLine(file, line)
	}
}

// --------------------
// OSINT search
// --------------------
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
		if perm == "" {
			continue
		}

		url := fmt.Sprintf("http://%s.s3.amazonaws.com", bucket)
		line := fmt.Sprintf("%s | %d | %s", url, code, perm)
		writeLine(file, line)
	}
}

// --------------------
// main
// --------------------
func main() {
	target := flag.String("t", "", "Target name (required)")
	wordlistFile := flag.String("w", "", "Wordlist file")
	outputFile := flag.String("o", "", "Output file")
	flag.BoolVar(&verbose, "v", false, "Verbose mode")
	flag.Parse()

	banner()

	if *wordlistFile == "" {
		*wordlistFile = "common_bucket_prefixes.txt"
	}

	if *target == "" {
		fmt.Println("Usage: s3-checker -t <target>")
		flag.PrintDefaults()
		os.Exit(1)
	}

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

	words, err := readWordlist(*wordlistFile)
	if err != nil {
		fmt.Println("Error reading wordlist:", err)
		return
	}

	wordlist := generateWordlist(*target, words)

	scanBuckets(wordlist, file)
	searchGrayHat(*target, file)
	searchOSINT(*target, file)
}
