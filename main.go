package main

import (
	"bufio"
	_ "embed"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed common_bucket_prefixes.txt
var embeddedWordlist string

const version = "v1.3.1"

// ================= COLORS =================

const (
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Cyan   = "\033[36m"
	Bold   = "\033[1m"
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
	statusFilter  int
	excludeStatus = map[int]struct{}{}
)

// ================= HELP MENU =================

func init() {
	flag.Usage = func() {
		fmt.Println(Bold + "s3-checker " + version + Reset)
		fmt.Println("Fast AWS S3 bucket discovery tool\n")

		fmt.Println(Bold + "Usage:" + Reset)
		fmt.Println("  s3-checker -t <target> [options]\n")

		fmt.Println(Bold + "Options:" + Reset)
		flag.PrintDefaults()

		fmt.Println("\n" + Bold + "Examples:" + Reset)
		fmt.Println("  s3-checker -t example")
		fmt.Println("  s3-checker -t example -c 200")
		fmt.Println("  s3-checker -t example -r 50")
		fmt.Println("  s3-checker -t example -s 200")
		fmt.Println("  s3-checker -t example -e 403")
		fmt.Println("  s3-checker -t example -w words.txt -o hits.txt")
	}
}

// ================= PARSE EXCLUDE =================

func parseExclude(input string) {
	if input == "" {
		return
	}
	parts := strings.Split(input, ",")
	for _, p := range parts {
		code, err := strconv.Atoi(strings.TrimSpace(p))
		if err == nil {
			excludeStatus[code] = struct{}{}
		}
	}
}

func isExcluded(code int) bool {
	_, ok := excludeStatus[code]
	return ok
}

// ================= BANNER =================

func printBanner(target string, total int, concurrency int, rate int) {
	banner := `
    ____   _____      _____ _               _
  / ___| |___ /     / ____| |__   ___  ___| | _____ _ __
  \___ \   |_ \____| |    | '_ \ / _ \/ __| |/ / _ \ '__|
   ___) | ___) |____| |___ | | | |  __/ (__|   <  __/ |
  |____/ |____/      \____||_| |_|\___|\___|_|\_\___|_|

            s3-checker — S3 Bucket Discovery Tool
		Developer - Abu Raihan Biswas
		Username - zapstiko
    s3-checker ` + version + `
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

	if statusFilter != 0 {
		fmt.Printf("[+] Status filter: %d\n", statusFilter)
	}
	if len(excludeStatus) > 0 {
		fmt.Printf("[+] Exclude codes: enabled\n")
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
		if statusFilter != 0 && code != statusFilter {
			continue
		}
		if isExcluded(code) {
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
	// Define flags
	target := flag.String("t", "", "Target name (required)")
	wordlistPath := flag.String("w", "", "Custom wordlist")
	outputPath := flag.String("o", "", "Output file")
	concurrency := flag.Int("c", 50, "Concurrency (workers)")
	rateLimit := flag.Int("r", 0, "Rate limit (req/sec)")
	exclude := flag.String("e", "", "Exclude status codes (comma-separated)")
	flag.IntVar(&statusFilter, "s", 0, "Filter by status code")
	showVersion := flag.Bool("v", false, "Show version and exit")

	flag.Parse()

	// Handle version flag
	if *showVersion {
		fmt.Printf("s3-checker %s\n", version)
		os.Exit(0)
	}

	parseExclude(*exclude)

	if *target == "" {
		flag.Usage()
		os.Exit(1)
	}

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

	var outFile *os.File
	if *outputPath != "" {
		outFile, err = os.Create(*outputPath)
		if err != nil {
			fmt.Println("Error creating output file:", err)
			os.Exit(1)
		}
		defer outFile.Close()
	}

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
