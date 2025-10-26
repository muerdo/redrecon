# RedRecon

**RedRecon** is a fast and flexible security orchestration tool built in Go. It automates security reconnaissance and scanning workflows by orchestrating a sequence of popular open-source tools to discover and analyze digital assets.

## Features

- **Modular Workflows**: Separate commands for different assessment stages (`recon`, `infra`, `web`, `scan`).
- **Comprehensive Reconnaissance**: Discovers subdomains, validates live hosts, collects URLs, and analyzes JavaScript files.
- **Web Application Crawling**: Downloads website content (JS, CSS, Source Maps) for offline analysis with depth control.
- **Endpoint & Secret Discovery**: Automatically extracts potential API endpoints from JavaScript files.
- **Intelligent Search**: A powerful `search` command to hunt for terms in result files with context, highlighting, and regex support.
- **Extensible**: Designed to integrate with popular external security tools (Subfinder, Nuclei, Nikto, Katana, etc.).
- **Configurable**: Uses a `config.yaml` file to manage tool settings, wordlists, and API keys.

## Installation

### 1. Install Go

RedRecon requires Go (version 1.21 or newer). You can download it from the official Go website.

### 2. Install External Tools

RedRecon orchestrates several external tools. You must install them and ensure they are available in your system's `PATH`. This tool is optimized for **Parrot OS** and **Kali Linux**, where most of these tools can be installed via `apt`.

```bash
# Install tools from package manager
sudo apt update && sudo apt install -y subfinder dnsutils nmap nuclei nikto whatweb

# Install Go-based tools
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsvalidator/cmd/dnsvalidator@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/tomnomnom/waybackurls@latest
```

### 3. Build redrecon-Go

Clone the repository and build the binary:

```bash
git clone https://github.com/YOUR_USERNAME/redrecon.git
cd redrecon
go build -o redrecon ./cmd/redrecon
```

You can move the `redrecon` binary to a directory in your `PATH` for easy access, like `/usr/local/bin/`.

## Configuration

1.  Copy the example configuration file:
    ```bash
    cp config.example.yaml config.yaml
    ```

2.  Edit `config.yaml` to add your API keys and customize paths to wordlists. This is crucial for tools like `subfinder` to work effectively.

## Usage

RedRecon is organized into several commands.

### Reconnaissance (`recon`)

Run a full reconnaissance workflow against a target domain.

```bash
# Run a full scan
./redrecon recon example.com

# Skip specific steps
./redrecon recon -s nikto -s bbot example.com
```

### Web Scan (`web`)

Crawl a website to download its assets for analysis.

```bash
# Crawl a website with default depth (2)
./redrecon web https://example.com

# Crawl with a specific depth
./redrecon web -d 5 https://example.com
```

### Search (`search`)

Search for terms within all generated result files.

```bash
# Find all occurrences of "password"
./redrecon search "password"

# Find potential API keys using regex, only in results for example.com
./redrecon search -t example.com -r "[a-fA-F0-9]{32}"

# List only the files containing the term "admin"
./redrecon search -l "admin"
```

### Scan (`scan`)

Run a focused Nuclei scan against a target.

```bash
# Scan for CVEs
./redrecon scan -t example.com -T cve

# Scan using a custom template
./redrecon scan -t example.com -T /path/to/my/template.yaml
```

## License

This project is licensed under the MIT License. See the LICENSE file for details.