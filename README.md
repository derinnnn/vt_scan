
# VT SCAN

VT SCAN is a Python-based tool that interfaces with the VirusTotal API to scan files, URLs, and IP addresses for potential indicators of compromise (IOCs). It is designed to provide detailed analysis and make cybersecurity investigations more efficient.

## Features

- **File Scanning**: Calculates the hash of a file and queries VirusTotal for analysis.
- **URL Scanning**: Checks URLs for malicious or suspicious activity.
- **IP Address Scanning**: Retrieves information about an IP address, such as country, ISP, and reputation.
- **Detailed Output**: Provides a formatted summary of scan results, including stats and metadata.
- **Verbose Mode**: Displays raw JSON responses for in-depth analysis.
- **Output Saving**: Allows users to save the results in JSON format.
- **Customizable Hash Algorithm**: Supports MD5 (default), SHA-1, and SHA-256 for file hash calculation.
- **Batch Input Support**: Can handle multiple inputs for files, URLs, or IP addresses.

## Installation

### Prerequisites
- Python 3.6+
- A VirusTotal API key (free or premium)

### Dependencies
Install the required Python libraries using pip:

```bash
pip install requests argparse tabulate colorama
```

## Usage

Run the script with the appropriate options to scan files, URLs, or IP addresses:

```bash
python vt_scan.py -t <type> -i <input> [options]
```

### Arguments

- `-t`, `--type`: Type of object to scan (`file`, `url`, or `ip`).
- `-i`, `--input`: Input to scan (file path, URL string, or IP address).
- `-a`, `--algorithm`: Hash algorithm for file scanning (`md5`, `sha1`, `sha256`). Default is `md5`.
- `-v`, `--verbose`: Enable verbose output (raw JSON response).
- `-o`, `--output`: Save results to a file (JSON format).

### Examples

#### File Scanning
```bash
python vt_scan.py -t file -i sample.exe
```

#### URL Scanning
```bash
python vt_scan.py -t url -i http://example.com
```

#### IP Address Scanning
```bash
python vt_scan.py -t ip -i 8.8.8.8
```

#### Verbose Output
```bash
python vt_scan.py -t url -i http://example.com -v
```

#### Save Results to File
```bash
python vt_scan.py -t ip -i 8.8.8.8 -o results.json
```

## Sample Inputs

### URLs
- `http://example.com`
- `http://testsite.com`

### IP Addresses
- `8.8.8.8`
- `1.1.1.1`

### Files
Use any file on your system to test.


---

Happy scanning!
```
