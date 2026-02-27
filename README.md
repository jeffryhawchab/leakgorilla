# LeakGorilla 🦍

**Advanced Web Secret Scanner for Security Professionals**

LeakGorilla is a powerful reconnaissance tool designed for penetration testers and security researchers to discover exposed API keys, credentials, and sensitive information in web applications. It intelligently crawls websites and analyzes HTML, JavaScript, and inline scripts to detect leaked secrets that could compromise security.

---

## 🎯 What is LeakGorilla?

LeakGorilla automates the tedious process of hunting for exposed secrets in web applications. During development, developers often accidentally commit API keys, tokens, and credentials to frontend code. LeakGorilla finds these security vulnerabilities before attackers do.

### Why Use LeakGorilla?

- **Automated Discovery**: Scans entire websites automatically, following links within the same domain
- **Comprehensive Detection**: Identifies 20+ types of secrets including AI API keys, cloud credentials, and database strings
- **Smart Analysis**: Scans HTML pages, external JavaScript files, and inline scripts
- **Concurrent Scanning**: Multi-threaded JavaScript file analysis for faster results
- **Safe Output**: Redacts sensitive data in console while saving full details to file
- **Flexible Export**: Supports both human-readable text and JSON formats

---

## 🔍 What LeakGorilla Detects

### AI & ML Services
- **OpenAI** API Keys (GPT, DALL-E, Whisper)
- **Anthropic Claude** API Keys
- **Groq** API Keys
- **Google AI** API Keys
- **Meta AI/Facebook** Access Tokens

### Cloud Providers
- **AWS** Access Keys & Secret Keys
- **Google Cloud** Service Account Keys
- **Azure** Connection Strings

### Development Tools
- **GitHub** Personal Access Tokens
- **GitLab** Tokens
- **Slack** Bot & User Tokens
- **JWT** Tokens

### Payment & Communication
- **Stripe** API Keys (Live & Test)
- **Twilio** API Keys
- **SendGrid** API Keys
- **Mailgun** API Keys

### Databases & Infrastructure
- **MongoDB** Connection Strings
- **PostgreSQL** Connection Strings
- **MySQL** Connection Strings
- **Redis** Connection Strings

### Security Assets
- **Private Keys** (RSA, EC, DSA, OpenSSH)
- **OAuth Tokens**
- **Generic API Keys & Secrets**

---

## 🚀 Quick Start

### Basic Scan
Scan a website for exposed secrets:
```bash
leakgorilla https://example.com
```

### Using Python Directly
If not installed via APT, run with Python:
```bash
python3 leakgorilla/scanner.py https://example.com
```

### Scan with Custom Depth
Scan up to 100 pages:
```bash
leakgorilla https://example.com --max-pages 100
```

### Export to JSON
Save results in JSON format for automation:
```bash
leakgorilla https://example.com --format json --output results.json
```

### Full Example
Comprehensive scan with all options:
```bash
leakgorilla https://target.com --max-pages 200 --timeout 15 --output scan_results.txt --format txt
```

---

## 📖 Usage Guide

### Command Syntax
```bash
leakgorilla <url> [options]
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `--max-pages N` | Maximum number of pages to crawl | 50 |
| `--timeout N` | HTTP request timeout in seconds | 10 |
| `--output FILE` | Output file path | web_secrets.txt |
| `--format FORMAT` | Output format: `txt` or `json` | txt |

### Examples

**1. Quick Security Audit (APT)**
```bash
leakgorilla https://myapp.com
```

**1. Quick Security Audit (Python)**
```bash
python3 leakgorilla/scanner.py https://myapp.com
```

**2. Deep Scan for Large Sites (APT)**
```bash
leakgorilla https://corporate-site.com --max-pages 500 --timeout 20 --delay 1
```

**2. Deep Scan for Large Sites (Python)**
```bash
python3 leakgorilla/scanner.py https://corporate-site.com --max-pages 500 --timeout 20 --delay 1
```

**3. Pentest with Proxy (APT)**
```bash
leakgorilla https://target.com --proxy http://127.0.0.1:8080 --verbose
```

**3. Pentest with Proxy (Python)**
```bash
python3 leakgorilla/scanner.py https://target.com --proxy http://127.0.0.1:8080 --verbose
```

**4. JSON Output for Automation (APT)**
```bash
leakgorilla https://api.example.com --format json --output api_secrets.json
```

**4. JSON Output for Automation (Python)**
```bash
python3 leakgorilla/scanner.py https://api.example.com --format json --output api_secrets.json
```

---

## 📊 Understanding Results

### Console Output
LeakGorilla displays progress in real-time:
```
[1/50] Scanning: https://example.com
  ✓ Found 3 potential secret(s)
[2/50] Scanning: https://example.com/about
[3/50] Scanning: https://example.com/api/config.js
  ✓ Found 1 potential secret(s)
```

### Summary Report
After scanning, you'll see a categorized summary:
```
================================================================================
SCAN SUMMARY
================================================================================
Total secrets found: 12

[OpenAI API Key] - 2 found
--------------------------------------------------------------------------------
  URL: https://example.com/js/app.js
  Source: JavaScript file
  Value: sk-pr...FJ2a

[AWS Access Key] - 1 found
--------------------------------------------------------------------------------
  URL: https://example.com/config
  Source: HTML content
  Value: AKIA...Z7Q9
```

### Output File
Full unredacted results are saved to your specified output file:
- **Text Format**: Human-readable with context snippets
- **JSON Format**: Machine-parsable for automation and integration

---

## 🎯 Use Cases

### 1. Pre-Deployment Security Check
Scan your staging environment before going live:
```bash
leakgorilla https://staging.myapp.com --max-pages 200
```

### 2. Bug Bounty Reconnaissance
Discover exposed secrets in target applications:
```bash
leakgorilla https://target.com --format json --output bounty_findings.json
```

### 3. Security Audit
Comprehensive scan of client websites:
```bash
leakgorilla https://client-site.com --max-pages 500 --timeout 20 --output audit_report.txt
```

### 4. Continuous Monitoring
Integrate into CI/CD pipelines:
```bash
leakgorilla https://production.app.com --format json | jq '.[] | select(.type=="OpenAI API Key")'
```

### 5. Competitor Analysis
Ethical reconnaissance (with permission):
```bash
leakgorilla https://competitor.com --max-pages 100
```

---

## 🛡️ Best Practices

### For Security Professionals
- Always get written permission before scanning
- Respect rate limits and server resources
- Use appropriate `--timeout` values
- Save results securely (they contain sensitive data)
- Report findings responsibly

### For Developers
- Run LeakGorilla on your own sites regularly
- Scan before each deployment
- Integrate into CI/CD pipelines
- Use `.env` files and environment variables instead of hardcoding secrets
- Implement secret scanning in pre-commit hooks

---

## ⚠️ Legal Disclaimer

**IMPORTANT**: Use LeakGorilla only on:
- Websites you own
- Systems you have explicit written permission to test
- Bug bounty programs that allow automated scanning

Unauthorized scanning may violate:
- Computer Fraud and Abuse Act (CFAA)
- Computer Misuse Act
- Terms of Service agreements
- Local and international laws

The developers of LeakGorilla are not responsible for misuse of this tool.

---

## 🔧 How It Works

1. **Crawling**: Starts at the target URL and discovers links within the same domain
2. **Content Extraction**: Downloads HTML pages and external JavaScript files
3. **Pattern Matching**: Uses advanced regex patterns to identify 20+ secret types
4. **Context Analysis**: Extracts surrounding code for better understanding
5. **Concurrent Processing**: Scans multiple JavaScript files simultaneously
6. **Smart Filtering**: Avoids binary files, images, and non-content URLs
7. **Safe Reporting**: Redacts secrets in console, saves full data to file

---

## 📈 Performance Tips

- **Start Small**: Use `--max-pages 10` for initial testing
- **Adjust Timeout**: Increase `--timeout` for slow servers
- **Monitor Progress**: Watch console output for real-time feedback
- **Use JSON**: Export to JSON for easier parsing and automation
- **Respect Servers**: Don't set `--max-pages` too high on small sites

---

## 🎯 Detection Accuracy

LeakGorilla uses regex patterns to detect secrets. Accuracy varies by secret type:

### High Accuracy (90-95%)
- ✅ OpenAI API Keys
- ✅ Anthropic Claude Keys
- ✅ Groq API Keys
- ✅ GitHub Tokens
- ✅ SendGrid API Keys
- ✅ AWS Access Keys

### Good Accuracy (80-90%)
- ✅ Stripe API Keys
- ✅ Slack Tokens
- ✅ Database Connection Strings
- ✅ Twilio API Keys

### Medium Accuracy (70-80%)
- ⚠️ Google API Keys
- ⚠️ Meta/Facebook Tokens
- ⚠️ JWT Tokens
- ⚠️ Private Keys

### Lower Accuracy (60-70%)
- ⚠️ Generic API Keys
- ⚠️ Generic Secrets

**Overall Accuracy: ~75-85%**

**Note**: False positives may occur with:
- Base64-encoded fonts/images
- Minified JavaScript
- Random strings in CSS files

**Recommendation**: Focus on **CRITICAL** and **HIGH** severity findings for best accuracy (85-95%).

---

## 🤝 Contributing

Found a bug or want to add detection for new secret types? Contributions welcome!

Repository: https://github.com/jeffryhawchab/leakgorilla

---

## 📄 License

MIT License - Copyright (c) 2026 Jeffrey Hawchab

---

## 🆘 Support

- **Issues**: https://github.com/jeffryhawchab/leakgorilla/issues
- **Documentation**: https://github.com/jeffryhawchab/leakgorilla/wiki

---

**Remember**: With great power comes great responsibility. Use LeakGorilla ethically and legally. 🦍
