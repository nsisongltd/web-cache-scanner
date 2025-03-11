# Web Cache Vuln Scanner

A high-performance, memory-efficient web cache vulnerability scanner written in Rust. This tool helps security professionals and penetration testers identify various web cache vulnerabilities including cache poisoning, cache deception, and timing attacks.

## Features

- 🚀 High-performance concurrent scanning
- 🔍 Detection of multiple cache vulnerability types:
  - Web Cache Poisoning
  - Cache Deception
  - Cache-based timing attacks
  - Cache key manipulation
  - Cache probing vulnerabilities
- 📊 Detailed reporting in multiple formats
- 🛠 Customizable scanning parameters
- 🧰 Extensive payload library
- 📝 Comprehensive logging
- 🔄 Automatic rate limiting

## Installation

### From Source
```bash
git clone https://github.com/nsisonglabs/web-cache-scanner
cd web-cache-scanner
cargo build --release
```

The binary will be available at `target/release/web-cache-scanner`

### From Cargo
```bash
cargo install web-cache-scanner
```

## Usage

Basic usage:
```bash
web-cache-scanner scan --url https://example.com
```

Advanced options:
```bash
web-cache-scanner scan \
  --url https://example.com \
  --threads 10 \
  --timeout 30 \
  --output report.json \
  --format json \
  --verbose
```

## Configuration

Create a `config.toml` file to customize scanner behavior:

```toml
[scanner]
threads = 10
timeout = 30
max_retries = 3

[http]
user_agent = "Cache-Scanner/1.0"
follow_redirects = true
verify_ssl = true

[reporting]
format = "json"
output_dir = "reports"
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security

If you discover any security-related issues, please email [security@nsisonglabs.com](mailto:security@nsisonglabs.com) instead of using the issue tracker.

## About

Built with ❤️ by [Nsisong Labs](https://nsisonglabs.com). We want to create high-performance security tools for the modern web. 