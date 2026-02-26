:::writing{variant=“standard” id=“91746”}

S3 Checker 🔍

A fast Go-based tool to bruteforce and discover AWS S3 buckets using smart permutations and OSINT sources. Built for bug bounty hunters and security researchers.

⸻

🧩 Description

s3-checker generates common bucket name permutations for a target and verifies their existence and permissions. It also enriches results using public bucket indexes.

Originally inspired by earlier S3 discovery techniques.

⸻

✨ Features
	•	Smart S3 permutation engine
	•	Permission detection (PUBLIC / PRIVATE)
	•	Full URL output
	•	GrayHatWarfare integration
	•	OSINT.sh integration
	•	Custom wordlist support
	•	Output file support
	•	Clean, grep-friendly output
	•	Go install ready

⸻

📦 Install

go install github.com/zapstiko/s3-checker@latest

Ensure your $GOPATH/bin is in your PATH.

⸻

🚀 Usage

s3-checker -t <COMPANY>

Examples

Basic scan:

s3-checker -t example

Save output:

s3-checker -t example -o buckets.txt

Custom wordlist:

s3-checker -t example -w custom.txt

With GrayHatWarfare API:

export GHW_API_KEY=your_api_key
s3-checker -t example


⸻

📤 Output Format

http://bucket.s3.amazonaws.com | 200 | PUBLIC
http://bucket.s3.amazonaws.com | 403 | PRIVATE


⸻

📁 Project Structure

s3-checker/
├── main.go
├── go.mod
├── common_bucket_prefixes.txt
└── README.md


⸻

🙏 Special Thanks
	•	http://twitter.com/nahamsec
	•	http://twitter.com/JobertAbma

⸻

⚠️ Disclaimer

This tool is intended only for authorized security testing and educational purposes.
Do not use against systems without proper permission.

The author assumes no liability for misuse.

⸻

⭐ Support

If this tool helped you, consider giving the repo a star.
:::
