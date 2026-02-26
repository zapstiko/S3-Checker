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

// ================= XML STRUCTS =================

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
		}
	}

	if content == "" {
		content = embeddedWordlist
	}

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			globalWordlist = append(globalWordlist, line)
		}
	}

	if len(globalWordlist) == 0 {
		return fmt.Errorf("wordlist empty")
	}
	return nil
}

// ================= S3 STRUCT =================

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

	switch resp.StatusCode {
	case 200, 403:
		return true, resp.StatusCode
	default:
		return false, resp.StatusCode
	}
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

// ================= PUBLIC CHECK =================

func isPublic(bucket string) bool {
	url := fmt.Sprintf("http://%s.s3.amazonaws.com/?list-type=2", bucket)

	resp, err := http.Get(url)
	if err == nil && resp.StatusCode == 200 {
		return true
	}
	if resp != nil {
		resp.Body.Close()
	}

	if useAWS {
		if _, err := exec.LookPath("aws"); err == nil {
			cmd := exec.Command(
				"aws", "s3", "ls",
				fmt.Sprintf("s3://%s", bucket),
				"--no-sign-request",
			)
			if err := cmd.Run(); err == nil {
				return true
			}
		}
	}

	return false
}

// ================= OBJECT STATS =================

func getBucketStats(bucket string) (int, int64) {
	url := fmt.Sprintf("http://%s.s3.amazonaws.com/?list-type=2", bucket)

	resp, err := http.Get(url)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return -1, 0
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var result ListBucketResult
	if err := xml.Unmarshal(body, &result); err != nil {
		return -1, 0
	}

	var total int64
	for _, obj := range result.Contents {
		total += obj.Size
	}

	return len(result.Contents), total
}

// ================= SIZE FORMAT =================

func humanSize(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
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

// ================= SCAN =================

func scanBuckets(list []string, file *os.File) {
	seen := make(map[string]bool)

	for _, word := range list {
		if seen[word] {
			continue
		}
		seen[word] = true

		s3 := NewS3(word)

		exists, _ := s3.Exists()
		if !exists {
			continue
		}

		region := s3.GetRegion()
		public := isPublic(word)

		if public {
			count, size := getBucketStats(word)
			line := fmt.Sprintf(
				"INFO exists | %s | %s | PUBLIC | AllUsers:[READ] | %d objects (%s)",
				s3.URL,
				region,
				count,
				humanSize(size),
			)
			writeLine(file, line)
		} else {
			line := fmt.Sprintf(
				"INFO exists | %s | %s | PRIVATE",
				s3.URL,
				region,
			)
			writeLine(file, line)
		}
	}
}

// ================= OUTPUT =================

func writeLine(file *os.File, line string) {
	fmt.Println(line)
	if file != nil {
		file.WriteString(line + "\n")
	}
}

// ================= MAIN =================

func main() {
	target := flag.String("t", "", "Target (required)")
	wordlistFile := flag.String("w", "", "Wordlist")
	outputFile := flag.String("o", "", "Output file")
	flag.BoolVar(&verbose, "v", false, "Verbose")
	flag.BoolVar(&useAWS, "aws", false, "Use AWS CLI")
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
