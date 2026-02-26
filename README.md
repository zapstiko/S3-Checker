# S3 Checker

Fast, focused AWS S3 bucket discovery and permission auditing tool written in Go.

S3 Checker generates high-probability bucket name permutations for a target, validates their existence, and classifies exposure level. It also enriches results using public bucket intelligence sources.


## Overview

S3 buckets are frequently exposed due to predictable naming patterns. **s3-checker** automates:

- Intelligent permutation generation  
- Bucket existence validation  
- Permission classification  
- OSINT enrichment  

Designed for bug bounty hunters, cloud security engineers, and red team operators.


## Features

- High-signal permutation engine  
- Permission detection (PUBLIC / PRIVATE)  
- Full virtual-host style URLs  
- GrayHatWarfare integration  
- OSINT.sh enrichment  
- Custom wordlist support  
- File output support  
- Grep-friendly output  
- Lightweight and fast  
- `go install` ready  

## Installation

### Using Go (recommended)

```bash
go install github.com/zapstiko/s3-checker@latest

Ensure your Go binary path is available:

export PATH=$PATH:$(go env GOPATH)/bin

```
## Build from source
```
git clone https://github.com/zapstiko/s3-checker.git
cd s3-checker
go build -o s3-checker

```

## Usage

### Basic scan
```
s3-checker -t <COMPANY>

Examples

Scan a target:

s3-checker -t google
```
### Save results:
```
s3-checker -t example -o buckets.txt
```
### Use custom wordlist:
```
s3-checker -t example -w custom.txt

```

### Enable GrayHatWarfare enrichment:
```
export GHW_API_KEY=your_api_key
s3-checker -t example
```

### Output Format
```
http://bucket.s3.amazonaws.com | 200 | PUBLIC
http://bucket.s3.amazonaws.com | 403 | PRIVATE
```
### Status Meaning
```
Status	Meaning
200	Publicly accessible bucket
403	Bucket exists but is private
```

### Project Structure
```
s3-checker/
├── main.go
├── go.mod
├── common_bucket_prefixes.txt
└── README.md
````

### Security & Ethics
```
This tool is intended strictly for authorized security testing and educational use.
	•	Always obtain proper permission
	•	Follow responsible disclosure
	•	Respect applicable laws and policies

The author assumes no liability for misuse.
````


### Acknowledgements
```
Special thanks to the security community:
	•	http://twitter.com/nahamsec
	•	http://twitter.com/JobertAbma

```

### Contributing
```
Pull requests and improvements are welcome. For major changes, please open an issue first to discuss what you would like to modify.

```

License

MIT License

