package main

import (
	"bufio"
	_ "embed"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed common_bucket_prefixes.txt
var embeddedWordlist string

const version = "v1.2.0"

// ================= COLORS =================

const (
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Cyan   = "\033[36m"
	Reset  = "\033[0m"
)

func colorStatus(code int) string {
	switch {
	case code >= 200 && code < 300:
		return Green
	case code >= 300 && code < 400:
		return Yellow
	case code >= 400 && code < 500:
		return Red
	default:
		return Cyan
	}
}

// ================= GLOBALS =================

var (
	client        = &http.Client{Timeout: 6 * time.Second}
	totalChecks   uint64
	statusInclude int
	statusExclude int
)

// ================= BANNER =================

func printBanner(target string, total int, concurrency int, rate int) {
	banner := `
   ____   _____      _____ _               _
  / ___| |___ /     / ____| |__   ___  ___| | _____ _ __
  \___ \   |_ \____| |    | '_ \ / _ \/ __| |/ / _ \ '__|
   ___) | ___) |____| |___ | | | |  __/ (__|   <  __/ |
  |____/ |____/      \____||_| |_|\___|\___|_|\_\___|_|

            s3-checker — S3 Bucket Discovery Tool
                 s3-checker ` + version + `
			   Developer - Abu Raihan Biswas 
				    Username - zapstiko
`
	fmt.Println(banner)
	fmt.Printf("[+] Target       : %s\n", target)
	fmt.Printf("[+] Candidates   : %d\n", total)
	fmt.Printf("[+] Concurrency  : %d\n", concurrency)

	if rate > 0 {
		fmt.Printf("[+] Rate limit   : %d req/sec\n", rate)
	} else {
		fmt.Printf("[+] Rate limit   : disabled\n")
	}

	if statusInclude != 0 {
		fmt.Printf("[+] Include code : %d\n", statusInclude)
	}
	if statusExclude != 0 {
		fmt.Printf("[+] Exclude code : %d\n", statusExclude)
	}

	fmt.Println()
}

// ================= S3 CHECK =================

func checkBucket(bucket string) (bool, int, string) {
	url := fmt.Sprintf("http://%s.s3.amazonaws.com", bucket)

	resp, err := client.Get(url)
	if err != nil {
		return false, 0, url
	}
	defer resp.Body.Close()

	code := resp.StatusCode
	return code != 404, code, url
}

// ================= WORDLIST =================

var environments = []string{
	"dev", "development", "stage", "s3",
	"staging", "prod", "production", "test",
}

func loadEmbeddedWordlist() []string {
	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(embeddedWordlist))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func loadCustomWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func generateWordlist(prefix string, words []string) []string {
	unique := make(map[string]struct{})
	unique[prefix] = struct{}{}

	envFormats := []string{
		"%s-%s-%s",
		"%s-%s.%s",
		"%s-%s%s",
		"%s.%s-%s",
		"%s.%s.%s",
	}

	hostFormats := []string{"%s.%s", "%s-%s", "%s%s"}

	for _, word := range words {
		for _, env := range environments {
			for _, f := range envFormats {
				unique[fmt.Sprintf(f, prefix, word, env)] = struct{}{}
			}
		}
	}

	for _, word := range words {
		for _, f := range hostFormats {
			unique[fmt.Sprintf(f, prefix, word)] = struct{}{}
			unique[fmt.Sprintf(f, word, prefix)] = struct{}{}
		}
	}

	var result []string
	for k := range unique {
		result = append(result, k)
	}
	return result
}

// ================= WORKER =================

func worker(jobs <-chan string, wg *sync.WaitGroup, outFile *os.File, rate <-chan time.Time) {
	defer wg.Done()

	for bucket := range jobs {
		if rate != nil {
			<-rate
		}

		exists, code, url := checkBucket(bucket)
		atomic.AddUint64(&totalChecks, 1)

		fmt.Printf("\r[+] Checked: %d", atomic.LoadUint64(&totalChecks))

		if !exists {
			continue
		}

		// include filter
		if statusInclude != 0 && code != statusInclude {
			continue
		}

		// exclude filter
		if statusExclude != 0 && code == statusExclude {
			continue
		}

		color := colorStatus(code)

		line := fmt.Sprintf(
			"%s [%s%d%s] [S3 Bucket Found]",
			url,
			color,
			code,
			Reset,
		)

		fmt.Printf("\r%s\n", line)

		if outFile != nil {
			outFile.WriteString(line + "\n")
		}
	}
}

// ================= MAIN =================

func main() {
	target := flag.String("t", "", "Target name (required)")
	wordlistPath := flag.String("w", "", "Custom wordlist")
	outputPath := flag.String("o", "", "Output file")
	concurrency := flag.Int("c", 50, "Concurrency")
	rateLimit := flag.Int("r", 0, "Rate limit (req/sec)")
	flag.IntVar(&statusInclude, "s", 0, "Include only this status code")
	flag.IntVar(&statusExclude, "e", 0, "Exclude this status code")
	flag.Parse()

	if *target == "" {
		fmt.Println("Usage: s3-checker -t <target>")
		os.Exit(1)
	}

	// wordlist selection
	var words []string
	var err error

	if *wordlistPath != "" {
		words, err = loadCustomWordlist(*wordlistPath)
		if err != nil {
			fmt.Println("Error loading wordlist:", err)
			os.Exit(1)
		}
	} else {
		words = loadEmbeddedWordlist()
	}

	wordlist := generateWordlist(*target, words)

	printBanner(*target, len(wordlist), *concurrency, *rateLimit)

	// output file
	var outFile *os.File
	if *outputPath != "" {
		outFile, err = os.Create(*outputPath)
		if err != nil {
			fmt.Println("Error creating output file:", err)
			os.Exit(1)
		}
		defer outFile.Close()
	}

	// rate limiter
	var rate <-chan time.Time
	if *rateLimit > 0 {
		rate = time.Tick(time.Second / time.Duration(*rateLimit))
	}

	jobs := make(chan string, *concurrency)
	var wg sync.WaitGroup

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go worker(jobs, &wg, outFile, rate)
	}

	for _, bucket := range wordlist {
		jobs <- bucket
	}
	close(jobs)

	wg.Wait()
	fmt.Printf("\n\nDone. Checked %d buckets.\n", totalChecks)
}
