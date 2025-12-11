# Email Validation Application

## Overview

The Email Validation Application is a tool designed to validate email addresses in real-time. It ensures that the email addresses entered by users are syntactically correct, conform to standard email formats, and organizations emails policy. This application can be integrated into web forms, sign-up processes, or any system that requires valid email inputs.
This Python tool for comprehensive email address validation with syntax checking, DNS verification, security analysism and security compliance.

## Features

### 🔍 Multi-Level Email Validation
- **Real-Time Validation**: Instantly checks the validity of an email address as it’s being entered.  
- **Syntax Checking**: Fully RFC 5322 compliant to ensure proper formatting (`username@domain.com`).  
- **Domain Verification**: Confirms the existence of domains and verifies MX, A, and AAAA DNS records.  
- **Security Analysis**: Evaluates SPF and DMARC records for email authentication and security.  
- **Typo Detection**: Detects and suggests corrections for common domain typos (e.g., `gmail.cmo` → `gmail.com`).  

### 🚀 High Performance
- **Bulk Validation**: Validates multiple email addresses simultaneously—ideal for mailing list cleanup.  
- **Parallel Processing**: Utilizes concurrent threads for efficient large-scale validation.  
- **DNS Query Caching**: Implements intelligent caching (5-minute TTL) to minimize redundant lookups.  
- **Rate Limiting**: Prevents DNS flooding and ensures stable, predictable performance.  
- **Duplicate Detection**: Identifies and removes repeated email addresses automatically.  

### 📊 Comprehensive Reporting
- **Flexible Output Formats**: Export results as Text, JSON, or CSV for easy analysis and integration.  
- **Validation Scoring**: Provides detailed validity scores (0–100) for each email.  
- **Summary Statistics**: Generates domain-level insights and validation performance summaries.  
- **Cache Metrics**: Monitors cache efficiency and DNS resolution hit rates.  

### 🛡️ Security & Intelligence
- **Disposable Email Detection**: Identifies temporary or throwaway email services.  
- **Free Provider Recognition**: Flags addresses from common free email services (e.g., Gmail, Yahoo).  
- **SPF/DMARC Validation**: Validates sender policy and message reliability.  
- **Custom Whitelist Support**: Allows trusted local or business domains to bypass external validation.  

### 🔗 API Integration
- **Simple RESTful API** for embedding validation logic into existing applications or workflows.  
- **Easy Integration** with web forms, CRMs, and backend systems.

## 📋 Requirements

- Python 3.7 or higher
- `dnspython` library

## 🚀 Installation

### Using pip
```bash
pip install dnspython
```

### From requirements.txt
```txt
dnspython>=2.4.0
python-dotenv==1.0.0
```

## 📁 Project Structure

```
email-validator/
├── email_validator.py    # Main validator class
├── main.py                # Command-line interface (this file)
├── requirements.txt      # Dependencies
├── .env         # Example environment variables
├── README.md             # This file
├── .gitignore

```

## 🎯 Quick Start

### Basic Usage
```bash
# Validate a single email
python main.py --emails "test@example.com"

# Validate multiple emails
python main.py --emails "user@gmail.com admin@company.com"

# Validate emails from a file
python main.py --file emails.txt

# Interactive mode (no arguments)
python main.py
```

## 💻 Command Line Usage

### Command Line Arguments

| Argument | Description | Default | Example |
|----------|-------------|---------|---------|
| `--emails` | Email addresses to validate (space separated) | - | `--emails "test@example.com user@gmail.com"` |
| `--file` | File containing emails (one per line) | - | `--file emails.txt` |
| `--parallel` | Enable/disable parallel processing | `True` | `--no-parallel` |
| `--format` | Output format: text, json, or csv | `text` | `--format json` |
| `--output` | Save report to file | Console | `--output report.json` |

### Examples

```bash
# Basic validation with text output
python main.py --emails "john.doe@company.com jane.smith@gmail.com"

# Validate from file with JSON output
python main.py --file user_emails.txt --format json

# Save CSV report to file
python main.py --file emails.txt --format csv --output validation_report.csv

# Disable parallel processing for debugging
python main.py --emails "test@example.com" --no-parallel

# Interactive mode with custom domains
python main.py
# Then enter: test@example.com user@gmail.com
# Then enter local domains: company.local internal.dev
```

## 🔧 Advanced Configuration

### Local Domain Configuration
When running in interactive mode, you can add local/internal domains that should bypass DNS validation:

```bash
# The tool will prompt for local domains
Enter your new domains separated by space: company.local internal.dev staging.example.com
```

### Validator Parameters
The validator can be customized with these parameters:

```python
validator = EnhancedEmailValidator(
    cache_ttl=300,          # DNS cache time-to-live (seconds)
    dns_timeout=5,          # DNS query timeout (seconds)
    max_workers=10,         # Maximum parallel workers
    rate_limit_delay=0.05   # Delay between DNS queries
)
```
## 🔧 Advanced Configuration

### Local Domain Configuration
When running in interactive mode, you can add local/internal domains that should bypass DNS validation:

```bash
# The tool will prompt for local domains
Enter your new domains separated by space: company.local internal.dev staging.example.com
```

### Validator Parameters
The validator can be customized with these parameters:

```python
validator = EnhancedEmailValidator(
    cache_ttl=300,          # DNS cache time-to-live (seconds)
    dns_timeout=5,          # DNS query timeout (seconds)
    max_workers=10,         # Maximum parallel workers
    rate_limit_delay=0.05   # Delay between DNS queries
)
```

## 📊 Output Formats

### 1. Text Format (Default)
```
==============================================================
EMAIL VALIDATION REPORT
==============================================================
Summary:
  Total emails: 5
  Unique emails: 4
  Valid: 3 (75.0%)
  Invalid: 1
  Validation time: 2.34 seconds
  Speed: 1.71 emails/second

--------------------------------------------------------------
Validation Details:
✅ VALID: john.doe@company.com
✅ VALID: jane.smith@gmail.com
❌ INVALID: invalid-email@
     Reason: Invalid email syntax
...
```

### 2. JSON Format
```json
{
  "total_emails": 5,
  "unique_emails": 4,
  "valid": 3,
  "invalid": 1,
  "validation_time": 2.34,
  "details": [
    {
      "email": "john.doe@company.com",
      "is_valid": true,
      "validation_level": "comprehensive",
      "details": {
        "syntax": {...},
        "domain": {...},
        "security": {
          "has_spf": true,
          "has_dmarc": true,
          "is_disposable": false,
          "overall_score": 90
        }
      }
    }
  ]
}
```

### 3. CSV Format
```csv
Email,Is Valid,Validation Level,Domain,Has SPF,Has DMARC,Is Disposable,Score
john.doe@company.com,True,comprehensive,company.com,True,True,False,90
jane.smith@gmail.com,True,comprehensive,gmail.com,True,True,False,90
invalid-email@,False,syntax,,False,False,False,0
```

## 🔍 Validation Details

### What Gets Checked
1. **Syntax Validation**
   - RFC 5322 compliant format
   - Proper @ symbol placement
   - Valid local part and domain
   - Length constraints (local ≤ 64 chars, total ≤ 254 chars)

2. **Domain Verification**
   - MX records (Mail Exchange)
   - A records (IPv4)
   - AAAA records (IPv6)
   - DNS connectivity and timeout handling

3. **Security Analysis**
   - SPF records (Sender Policy Framework)
   - DMARC records (Domain-based Message Authentication)
   - Disposable email domain detection
   - Free email provider identification

### Validation Score
Each email receives a score (0-100) based on:
- **30 points**: Valid syntax
- **40 points**: Valid domain with MX/A/AAAA records
- **10 points**: SPF record present
- **10 points**: DMARC record present
- **10 points**: Not a disposable domain

## 🚫 Disposable Email Domains Detected
The validator automatically flags emails from known disposable/temporary email services:
- mailinator.com
- tempmail.com
- guerrillamail.com
- 10minutemail.com
- yopmail.com
- ...and 40+ others

## 🏢 Free Email Providers Identified
Common free email services are identified for business/enterprise use:
- gmail.com
- yahoo.com
- outlook.com
- hotmail.com
- icloud.com
- protonmail.com
- ...and 10+ others

## ⚡ Performance Tips

### For Large Email Lists
```bash
# Use parallel processing (default)
python cli.py --file large_list.txt --format json --output results.json

# Adjust workers based on your system
# In email_validator.py, modify: max_workers=cpu_count() * 2
```

### Cache Management
- DNS results are cached for 5 minutes (configurable)
- Cache statistics are displayed after each run
- Clear cache: `validator.clear_cache()`

## 🔧 Integration Examples

### Python Script Integration
```python
from email_validator import EnhancedEmailValidator

# Initialize validator
validator = EnhancedEmailValidator()

# Add local domains
validator.local_domains.update(['company.local', 'internal.dev'])

# Validate single email
result = validator.validate_email("user@example.com")
if result.is_valid:
    print(f"Valid email with score: {result.details['overall_score']}")

# Validate bulk emails
emails = ["test1@example.com", "test2@gmail.com", "invalid@"]
results = validator.validate_bulk_emails(emails, parallel=True)
print(f"Valid: {results['valid']}, Invalid: {results['invalid']}")
```

### Web Application Integration with flask
```python
from flask import Flask, request, jsonify
from email_validator import EnhancedEmailValidator

app = Flask(__name__)
validator = EnhancedEmailValidator()

@app.route('/validate', methods=['POST'])
def validate_email():
    email = request.json.get('email')
    if not email:
        return jsonify({"error": "Email required"}), 400
    
    result = validator.validate_email(email)
    return jsonify(result.to_dict())

@app.route('/validate-bulk', methods=['POST'])
def validate_bulk():
    emails = request.json.get('emails', [])
    results = validator.validate_bulk_emails(emails)
    return jsonify(results)
```

## 🐛 Troubleshooting

### Common Issues

1. **DNS Resolution Failures**
   ```
   Error: No nameservers for domain: example.com
   ```
   **Solution**: Check internet connectivity or configure custom DNS resolvers.

2. **Slow Validation**
   ```
   Validation time: 30.5 seconds for 10 emails
   ```
   **Solution**: 
   - Reduce `dns_timeout` (default: 5 seconds)
   - Increase `rate_limit_delay` for rate-limited DNS
   - Check DNS server responsiveness

3. **Import Errors**
   ```
   ModuleNotFoundError: No module named 'dns'
   ```
   **Solution**: Install dnspython: `pip install dnspython`

### Debug Mode
For detailed logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 📈 Performance Benchmarks

| Emails | Parallel | Time | Speed |
|--------|----------|------|-------|
| 10 | Yes | 2.1s | 4.8 emails/s |
| 10 | No | 5.3s | 1.9 emails/s |
| 100 | Yes | 12.4s | 8.1 emails/s |
| 100 | No | 52.7s | 1.9 emails/s |

*Tested on: Python 3.9, 8-core CPU, 100Mbps internet*

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

### Development Setup
```bash
git clone https://github.com/gkpazahi/email-validator.git
cd email-validator
pip install -r requirements.txt
```
## 📄 License
This project is licensed under the [MIT License](LICENSE).

Copyright (c) [2025] [Gao Kpazahi]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights  
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell  
copies of the Software, and to permit persons to whom the Software is  
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included  
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR  
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE  
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER  
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING  
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS  
IN THE SOFTWARE.


## 🙏 Acknowledgments

- [RFC 5322](https://tools.ietf.org/html/rfc5322) - Internet Message Format
- [dnspython](https://www.dnspython.org/) - DNS toolkit for Python
- [Disposable Email Domains](https://github.com/ivolo/disposable-email-domains) - For the disposable domain list


Found a bug? Have a feature request?
- [Open an Issue](https://github.com/gkpazahi/email-validator/issues)
- Email: support@example.com

*Happy Validating your emails!
