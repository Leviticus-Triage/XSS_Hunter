# XSS Hunter Pro Framework - Documentation

## Overview

The XSS Hunter Pro Framework is a comprehensive tool for detecting and exploiting Cross-Site Scripting (XSS) vulnerabilities in web applications.
It offers advanced features such as machine learning for payload generation, WAF detection and bypass, as well as detailed validation of discovered vulnerabilities.

**Current Status:**
Under heavy development — BETA
So don't complain, just contribute! 😉

---

## Installation

### Requirements

- Python 3.8 or higher
- pip (Python package manager)


### Install Dependencies

```bash
pip install -r requirements.txt
```

The `requirements.txt` file contains the following dependencies:

```
requests&gt;=2.25.1
beautifulsoup4&gt;=4.9.3
colorama&gt;=0.4.4
jinja2&gt;=3.0.1
urllib3&gt;=1.26.5
selenium&gt;=4.0.0
pillow&gt;=8.2.0
```


### Create a Virtual Python Environment

```bash
python3 -m [venv-name]
source [venv-name]/bin/activate
```

---

## Usage

The framework offers different modes for various use cases:

### Scan Mode

Scan a website for XSS vulnerabilities.

```bash
python main.py --mode scan --url https://example.com --depth 2 --xss-types all --screenshot --use-ml
```


### Exploit Mode

Exploit a known XSS vulnerability.

```bash
python main.py --mode exploit --url https://example.com --param q --exploit-type reflected_xss --verify
```


### Payload Mode

Generate XSS payloads for different contexts.

```bash
python main.py --mode payload --context html --complexity 3 --size 10
```


### Report Mode

Generate reports from existing scan results.

```bash
python main.py --mode report --input ./output/results/vulnerabilities.json --format html
```

---

## Command Line Arguments

The framework supports the following command-line arguments:

### General Arguments

| Argument | Description | Default Value |
| :-- | :-- | :-- |
| `--help`, `-h` | Display help | - |
| `--version` | Display version | - |
| `--mode` | Operation mode (scan, exploit, payload, report) | scan |
| `--verbose` | Verbose output | False |
| `--output-dir` | Output directory | ./output |
| `--debug` | Enable debug mode | False |

---

## Troubleshooting

### Common Issues and Solutions

#### 1. Missing Modules

**Problem:** Error messages like "Module could not be imported."

**Solution:** Ensure all dependencies are installed:

```bash
pip install -r requirements.txt
```

For browser automation (screenshots):

```bash
pip install selenium webdriver-manager
```


#### 2. WAF Detection and Bypass Issues

**Problem:** WAF blocks requests.

**Solution:** Use the WAF bypass functions:

```bash
python main.py --mode scan --url https://example.com --waf-bypass
```


#### 3. False Positive XSS Findings

**Problem:** Framework reports XSS vulnerabilities that are not exploitable.

**Solution:** Increase the validation level and enable verification:

```bash
python main.py --mode scan --url https://example.com --verify-xss
```


#### 4. ML Module Errors

**Problem:** Errors when using the ML module.

**Solution:** Ensure required ML dependencies are installed:

```bash
pip install numpy scikit-learn
```


#### 5. Callback Server Problems

**Problem:** Callback server does not start or is unreachable.

**Solution:** Check if the port is available and no firewall blocks access:

```bash
python main.py --mode scan --url https://example.com --callback-server --callback-port 8091
```

---

## Advanced Features

### WAF Detection and Bypass

The framework can detect Web Application Firewalls (WAFs) and apply techniques to bypass them:

```bash
python main.py --mode scan --url https://example.com --waf-detect --waf-bypass
```


### Machine Learning

The framework uses machine learning to improve payload generation and vulnerability detection:

```bash
python main.py --mode scan --url https://example.com --use-ml
```


### XSS Validation

The framework offers various validation levels for XSS vulnerabilities:

```bash
python main.py --mode scan --url https://example.com --verify-xss --verify-level 3
```

Validation levels:

- **0:** No validation (accept all findings)
- **1:** Basic validation (marker must be present in the response)
- **2:** Standard validation (marker must be present in the response, and context must be identifiable)
- **3:** Strict validation (marker must be present in the response, context must be identifiable, and payload must be executable)

---

## Output Formats

The framework can output results in various formats:

### JSON Format

```json
{
  "scan_info": {
    "url": "https://example.com",
    "timestamp": "2025-03-31T08:00:00Z",
    "duration": 120
  },
  "vulnerabilities": [
    {
      "type": "reflected_xss",
      "url": "https://example.com/search",
      "parameter": "q",
      "payload": "&lt;script&gt;alert('XSS')&lt;/script&gt;",
      "severity": "HIGH",
      "description": "Reflected Cross-Site Scripting (XSS) vulnerability in HTML context",
      "exploitation": "To exploit this vulnerability...",
      "screenshot": "/path/to/screenshot.png",
      "verified": true
    }
  ]
}
```


### HTML Report

The framework generates detailed HTML reports with:

- Summary of results.
- Detailed description of each vulnerability.
- Screenshots (if enabled).
- Reproduction steps.
- Recommendations for mitigation.

---

## Best Practices

### For Scanning

1. Start with a passive scan to understand the target:

```bash
python main.py --mode scan --url https://example.com --scan-type passive
```

2. Perform a full scan with moderate depth:

```bash
python main.py --mode scan --url https://example.com --depth 2 --xss-types all
```

3. Enable ML for better results:

```bash
python main.py --mode scan --url https://example.com --use-ml
```

4. Verify discovered vulnerabilities:

```bash
python main.py --mode exploit --url https://example.com --param q --verify-xss 
```


---

## License

MIT License
