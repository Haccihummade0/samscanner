# SAMSCAN WEBTOOL 

# Comprehensive Reconnaissance Scanner
A Python script designed for cybersecurity researchers and developers to quickly map the attack surface of a target domain by collecting a wide range of useful reconnaissance data. This tool helps in identifying potential vulnerabilities and understanding the target's infrastructure.

## ✨ Features

*   **Website Connectivity Test**: Attempts to connect to the target domain using various HTTP/HTTPS and WWW combinations to identify the primary working URL.
*   **Technology Detection**: Analyzes HTTP headers and HTML content to identify web servers (Apache, Nginx, IIS), programming languages & frameworks (PHP, ASP.NET, Node.js, Laravel), and Content Management Systems (CMS) like WordPress, Joomla, Drupal. Includes detection for frontend frameworks (React, Vue, Angular) and analytics tools.
*   **Open Index Directory Checks**: Scans for common publicly accessible directories (e.g., `/uploads`, `/admin`, `/backup`) that might expose sensitive information.
*   **Sensitive File Discovery**: Attempts to locate common sensitive files like `.env`, `database.sql`, `config.php`, `wp-config.php`, and more.
*   **Port Scanning with Service Probing**: Resolves the domain to an IP address and scans common ports (e.g., 21, 22, 80, 443, 3306) to detect open ports and grab service banners.
*   **Subdomain Enumeration**: Employs multiple techniques to uncover subdomains, including:
    *   Brute force with common subdomain names.
    *   Leveraging `crt.sh` certificate transparency logs.
    *   Analyzing `robots.txt` and `sitemap.xml` files.
    *   Basic Virtual Host Scanning (VHost) against the target IP.
    *   Reverse IP Lookup (for co-hosted domains).
*   **Comprehensive Web Spidering**: Recursively crawls accessible links within the target domain to discover hidden paths and additional content, reporting forms found on pages.
*   **Real-time CLI Logging**: Provides detailed, colored output directly to your terminal, showing progress and findings as they happen.
*   **Detailed HTML Report Generation**: At the end of the scan, a comprehensive HTML report is generated, consolidating all collected reconnaissance data, including clickable links for discovered subdomains and an exhaustive log of all scanned URLs with their HTTP status codes.

## ⚠️ Prerequisites

*   Python 3.8 or higher.

## ⚙️ Installation

1.  **Clone the repository** (or download the `samscan.py` script):
    ```bash
    git clone https://github.com/Haccihummade0/samscanner.git
    cd samscanner
    ```
    
2.  **Install the required Python packages**:
    ```bash
    pip install -r requirements.txt
    ```
    This command will install `requests`, `beautifulsoup4`, and `colorama`.

## 🚀 Usage

1.  **Run the script** from your terminal:
    ```bash
    python samscan.py
    ```

2.  **Enter the target domain** when prompted (e.g., `example.com`).

    The script will then proceed with all scan phases, displaying progress and findings in your terminal with colorized output.

## 📈 HTML Report

Upon completion, a detailed HTML report will be generated in the same directory where you run the script. The report filename will follow the format: `[target_domain_underscored]_scan_report.html` (e.g., `example_com_scan_report.html`).

This report provides a well-organized overview of all findings, making it easy to review and share the reconnaissance data. It includes clickable links for identified subdomains and directories, port scan details, and a full console log for reference.

## ⚖️ Disclaimer

This script is **designed for cybersecurity researchers, developers, and educational purposes only**.

*   **Ethical Use**: Always ensure you have **explicit permission** from the domain owner or responsible party before scanning any target. Unauthorized scanning may be illegal and unethical.
*   **SSL Verification (`verify=False`)**: The script intentionally uses `verify=False` for `requests` to bypass SSL/TLS certificate validation. This is done to allow connections to sites with self-signed, expired, or otherwise problematic certificates that might prevent a standard scan. **Be aware that disabling SSL verification removes a critical security layer and can expose your connection to Man-in-the-Middle (MitM) attacks.** Do NOT use this feature for sensitive data transfers or in production environments where secure communication is paramount.
*   **Exploit Testing**: This tool focuses on **reconnaissance and information gathering**. It performs **service detection and banner grabbing on ports**, but it does **NOT execute exploits** or perform any invasive or destructive testing. Direct "exploit testing" implies intrusive actions that should only be performed with explicit authorization and a full understanding of the ethical and legal implications.

**Use this tool responsibly and with proper authorization.**
