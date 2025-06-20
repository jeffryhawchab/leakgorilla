

Web Secret Scanner
==================

A powerful Python tool that crawls websites and scans for exposed API keys, credentials, and other sensitive information in HTML and JavaScript files.

Features
--------

*   Crawls websites recursively (stays within same domain)
*   Scans both HTML content and external JavaScript files
*   Detects 20+ types of secrets (API keys, tokens, credentials)
*   Redacts sensitive output in console
*   Saves full results to file
*   Configurable scanning depth

Installation
------------

### 1\. Clone the repository:

    git clone https://github.com/jeffryhawchab/leakgorilla.git
    cd web-secret-scanner

### 2\. Set up the environment:

    # Create virtual environment
    python -m venv env
    
    # Activate environment
    source env/bin/activate  # Linux/Mac
    .\env\Scripts\activate  # Windows

### 3\. Install dependencies:

    pip install -r requirements.txt

Usage
-----

### Basic scan:

    python3 main.py https://example.com

### Advanced options:

    python scanner.py https://example.com --max-pages 100 --timeout 15 --output results.txt




### Legal Disclaimer

Use this tool only on websites you own or have permission to scan. Unauthorized scanning may violate laws and terms of service.

Output
------

Results are saved to `web_secrets.txt` with:

*   URL where secret was found
*   Source (HTML/JS)
*   Secret type
*   Full secret value

Console shows redacted versions for safety.



