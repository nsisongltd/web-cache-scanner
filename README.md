# Web Cache Vulnerability Scanner

An advanced, high-performance web cache vulnerability scanner written in Rust. This tool helps security professionals and penetration testers identify web cache vulnerabilities including cache poisoning, cache deception, and cache timing attacks.

## Features

- **Comprehensive Vulnerability Detection**
  - Cache Poisoning Detection
  - Cache Deception Testing
  - Cache Timing Analysis
  - Cache Key Manipulation
  - Cache Probing
  - Parameter Cloaking Detection

- **Advanced Scanning Capabilities**
  - Concurrent scanning with configurable thread count
  - Rate limiting support
  - Proxy support (HTTP/SOCKS)
  - Custom header and cookie injection
  - Path-based scanning
  - Recursive crawling
  - Custom wordlist support

- **Flexible Configuration**
  - YAML-based configuration files
  - Command-line interface
  - Environment variable support
  - Multiple output formats (JSON, HTML, Markdown)

- **Detailed Reporting**
  - Vulnerability descriptions
  - CVSS scores
  - Proof of Concept (PoC) commands
  - Remediation suggestions
  - References to related research
  - Evidence collection

## Installation

### From Source
```bash
# Clone the repository
git clone https://github.com/nsisongltd/web-cache-vulnerability-scanner
cd web-cache-vulnerability-scanner

# Build in release mode
cargo build --release

# Install globally
cargo install --path .
```

### From Cargo
```bash
cargo install web-cache-vulnerability-scanner
```

## Usage

### Basic Scan
```bash
wcvs scan example.com
```

### Advanced Options
```bash
# Scan with custom threads and timeout
wcvs scan example.com --threads 20 --timeout 60

# Use custom headers and cookies
wcvs scan example.com -H "X-Forward-For: 127.0.0.1" -H "User-Agent: Custom" --cookies "session=abc123"

# Enable debug logging
wcvs scan example.com --debug

# Generate HTML report
wcvs scan example.com --format html --output report.html

# Use proxy
wcvs scan example.com --proxy http://127.0.0.1:8080

# Scan with authentication
wcvs scan example.com --auth username:password

# Custom wordlist
wcvs scan example.com --wordlist paths.txt
```

### Configuration File
```bash
# Generate sample configuration
wcvs generate-config config.yaml

# Validate configuration
wcvs validate-config config.yaml

# Run scan with configuration
wcvs scan example.com --config config.yaml
```

## Configuration

Example configuration file (config.yaml):
```yaml
scan:
  threads: 10
  timeout: 30
  follow_redirects: true
  max_redirects: 10
  verify_ssl: true
  rate_limit: 50
  depth: 2
  passive: false
  paths: []
  exclude_paths: []
  wordlists:
    paths: null
    parameters: null
    headers: null

http:
  headers: []
  cookies: []
  user_agent: "Web-Cache-Scanner/1.0 (Nsisong Labs)"
  proxy: null
  auth: null

reporting:
  format: html
  output_dir: reports
  include_evidence: true
  include_references: true
```

## Vulnerability Types

### Cache Poisoning
- Unkeyed header injection
- Parameter cloaking
- Cache key manipulation

### Cache Deception
- Path confusion
- Content-type confusion
- Resource mapping

### Cache Timing
- Response time analysis
- Cache hit/miss detection
- Side-channel vulnerabilities

### Cache Probing
- Sensitive path detection
- Cache key enumeration
- Access control bypass

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [PortSwigger Web Security - Web Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning)
- [OWASP Web Cache Deception Attack](https://owasp.org/www-community/attacks/Cache_Deception)
- [CWE-444: Inconsistent Interpretation of HTTP Requests](https://cwe.mitre.org/data/definitions/444.html)

## Security

For security issues, please email security@nsisonglabs.com or open a security advisory on GitHub. 