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

var environments = []string{
	"dev", "development", "stage", "s3",
	"staging", "prod", "production", "test",
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
	resp, err := s.Client.Get(s.Domain)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()

	code := resp.StatusCode

	switch code {
	case 200:
		return code, "PUBLIC"
	case 403:
		return code, "PRIVATE"
	default:
		return code, ""
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
// Local scanner
// --------------------
func scanBuckets(list []string, output string) {
	var file *os.File
	var err error

	if output != "" {
		file, err = os.Create(output)
		if err != nil {
			fmt.Println("Error creating output file:", err)
			return
		}
		defer file.Close()
	}

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
func searchGrayHat(keyword string) {
	apiKey := os.Getenv("GHW_API_KEY")
	if apiKey == "" {
		return
	}

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
		fmt.Printf("%s | %d | %s\n", url, code, perm)
	}
}

// --------------------
// OSINT.SH search
// --------------------
func searchOSINT(keyword string) {
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
		fmt.Printf("%s | %d | %s\n", url, code, perm)
	}
}

// --------------------
// main
// --------------------
func main() {
	target := flag.String("t", "", "Target name (required)")
	wordlistFile := flag.String("w", "", "Wordlist file")
	outputFile := flag.String("o", "", "Output file")
	flag.Parse()

	if *wordlistFile == "" {
		*wordlistFile = "common_bucket_prefixes.txt"
	}

	if *target == "" {
		fmt.Println("Usage: s3-finder -t <target>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	words, err := readWordlist(*wordlistFile)
	if err != nil {
		fmt.Println("Error reading wordlist:", err)
		return
	}

	wordlist := generateWordlist(*target, words)

	scanBuckets(wordlist, *outputFile)
	searchGrayHat(*target)
	searchOSINT(*target)
}