import requests
import socket
import re
from urllib.parse import urlparse, urljoin
import os
import sys
from datetime import datetime

# Import and initialize colorama at the very beginning
import colorama
colorama.init() # This makes ANSI escape codes work on Windows terminals

# Disable insecure request warnings when verify=False is used
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# --- Global Variables for Scan Results and Console Logging ---
scan_results = {
    "target_domain": "",
    "target_ip": "",
    "primary_url": "",
    "detected_technologies": [],
    "open_index_directories": [],
    "accessible_sensitive_files": [],
    "port_scan_results": [],
    "found_subdomains": [],
    "console_log": [],
    "scanned_links": [], # Stores all HTTP/S requests made by the script for report
    "spider_visited_urls": set() # Use a set to keep track of visited URLs during spidering
}

# --- ANSI Escape Codes for Console Colors ---
# These remain the same, colorama will intercept them
ANSI_COLORS = {
    "black": "\033[30m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "white": "\033[37m",
    "reset": "\033[0m"
}

def log_console(message, color="white"):
    """
    Appends message to the HTML-friendly console log list and prints it to the actual console with ANSI colors.
    """
    # Print to actual console with ANSI colors using the global ANSI_COLORS
    console_message = f"{ANSI_COLORS.get(color, ANSI_COLORS['white'])}{message}{ANSI_COLORS['reset']}"
    print(console_message)

    # Store for HTML report (strip ANSI codes, add HTML color span class)
    html_message = f'<span class="{color}">{message}</span>'
    scan_results["console_log"].append(html_message)

# (The rest of your script remains the same)

def add_scanned_link(url, status_code, link_type="", detected_file_extension=None):
    """Adds a link to the scanned_links list for the HTML report."""
    scan_entry = {
        "url": url,
        "status_code": status_code,
        "type": link_type
    }
    if detected_file_extension:
        scan_entry["file_ext"] = detected_file_extension
    
    # Avoid adding duplicates if the same exact URL was scanned from multiple phases (e.g., direct check and spider)
    # This simplified check considers the URL only, more robust could use (URL, type) tuple for uniqueness
    if any(entry["url"] == url for entry in scan_results["scanned_links"]):
        return

    scan_results["scanned_links"].append(scan_entry)

def resolve_domain(domain):
    log_console(f"Resolving IP address for {domain}...", "blue")
    try:
        ip_address = socket.gethostbyname(domain)
        scan_results["target_ip"] = ip_address
        log_console(f"Resolved {domain} to {ip_address}", "green")
        return ip_address
    except socket.gaierror as e:
        log_console(f"Error resolving domain {domain}: {e}", "red")
        return None

def connect_to_website(domain):
    log_console(f"Attempting to connect to {domain}...", "blue")
    schemes = ["https://", "http://"]
    www_prefixes = ["", "www."]

    for scheme in schemes:
        for prefix in www_prefixes:
            url = f"{scheme}{prefix}{domain}"
            log_console(f"Trying: {url}", "cyan")
            try:
                # IMPORTANT: verify=False added to handle SSL issues
                response = requests.get(url, timeout=15, allow_redirects=True, verify=False)
                
                # Store the *final* URL after redirects
                final_url = response.url 
                
                add_scanned_link(final_url, response.status_code, "Initial Connection")

                if response.status_code in [200, 301, 302, 403]: # Considered a connection for scanning purposes
                    scan_results["primary_url"] = final_url
                    log_console(f"Successfully connected to {scan_results['primary_url']} (Status: {response.status_code})", "green")
                    return response
            except requests.exceptions.RequestException as e:
                log_console(f"Failed to connect to {url}: {e}", "yellow")
                add_scanned_link(url, f"Error: {type(e).__name__}", "Initial Connection Failed")

    log_console(f"Failed to connect to {domain} via any standard URL.", "red")
    return None

def detect_technologies(response):
    log_console("Detecting website technologies...", "blue")
    if not response:
        log_console("No website response available for technology detection.", "yellow")
        return

    detected = []
    headers = response.headers
    html_content = response.text.lower()

    # --- Header Analysis ---
    if "Server" in headers:
        server_val = headers["Server"].lower()
        if "nginx" in server_val: detected.append("Web Server: Nginx")
        elif "apache" in server_val: detected.append("Web Server: Apache")
        elif "iis" in server_val: detected.append("Web Server: IIS")
        else: detected.append(f"Web Server: {server_val.capitalize()}")

    if "X-Powered-By" in headers:
        powered_by_val = headers["X-Powered-By"].lower()
        if "php" in powered_by_val: detected.append("Language: PHP")
        elif "asp.net" in powered_by_val: detected.append("Framework/Language: ASP.NET")
        elif "express" in powered_by_val or "nodejs" in powered_by_val: detected.append("Framework: Node.js (Express)")
        else: detected.append(f"Powered By: {powered_by_val.capitalize()}")

    if "Set-Cookie" in headers:
        if "wordpress" in headers["Set-Cookie"].lower(): detected.append("CMS: WordPress (via Cookie)")
        elif "joomla" in headers["Set-Cookie"].lower(): detected.append("CMS: Joomla (via Cookie)")
        elif "laravel_session" in headers["Set-Cookie"].lower(): detected.append("Framework: Laravel")
        if "asp.net" in headers["Set-Cookie"].lower() and ".net" not in headers.get("X-Powered-By", "").lower():
            detected.append("Framework/Language: ASP.NET (via Cookie)") # Catch if not in X-Powered-By

    # --- HTML Content Analysis ---
    if "wp-content" in html_content or "wp-includes" in html_content or 'wordpress' in html_content:
        if "CMS: WordPress" not in detected: detected.append("CMS: WordPress")
    if "joomla!" in html_content or "/media/com_joomla/" in html_content or 'joomla.xml' in html_content:
        if "CMS: Joomla" not in detected: detected.append("CMS: Joomla")
    if "drupal.org" in html_content or "/sites/default/files/" in html_content or 'drupal' in html_content:
        if "CMS: Drupal" not in detected: detected.append("CMS: Drupal")
    
    if "generator" in html_content:
        generator_match = re.search(r'name="generator" content="([^"]+)"', html_content)
        if generator_match:
            gen_val = generator_match.group(1).lower()
            if 'wordpress' in gen_val and "CMS: WordPress" not in detected: detected.append("CMS: WordPress")
            elif 'joomla' in gen_val and "CMS: Joomla" not in detected: detected.append("CMS: Joomla")
            elif 'drupal' in gen_val and "CMS: Drupal" not in detected: detected.append("CMS: Drupal")
            else: detected.append(f"Generator: {generator_match.group(1)}")
    
    # Frontend/Other Frameworks and Technologies
    if 'data-vue-app' in html_content or 'vue.min.js' in html_content or 'var _vue' in html_content: detected.append('Frontend Framework: Vue.js')
    if 'data-reactroot' in html_content or 'react.production.min.js' in html_content or 'react-dom' in html_content: detected.append('Frontend Framework: React')
    if 'ng-app' in html_content or 'angular.json' in response.url: detected.append('Frontend Framework: Angular')
    if 'cdn.shopify.com' in html_content: detected.append("E-commerce: Shopify")
    if 'woocommerce' in html_content: detected.append("E-commerce: WooCommerce (WordPress Plugin)")
    if 'google-analytics.com/analytics.js' in html_content or 'googletagmanager.com' in html_content: detected.append("Analytics: Google Analytics")
    if 'gtm.js' in html_content: detected.append("Tag Manager: Google Tag Manager")
    if '<meta name="twitter:' in html_content: detected.append("Social Meta: Twitter Cards")
    if '<meta property="og:' in html_content: detected.append("Social Meta: Open Graph (Facebook)")
    if re.search(r'(phpmyadmin|pma)', html_content): detected.append("Admin Interface: phpMyAdmin")
    if re.search(r'adminer.css', html_content): detected.append("Admin Interface: Adminer")


    # Remove duplicates
    scan_results["detected_technologies"] = list(set(detected))
    if scan_results["detected_technologies"]:
        log_console("Detected Technologies:", "green")
        for tech in scan_results["detected_technologies"]:
            log_console(f"  - {tech}")
    else:
        log_console("No specific technologies detected.", "yellow")

def check_open_index_directories(primary_url):
    log_console("Checking for open index directories...", "blue")
    common_directories = [
        "uploads/", "files/", "backup/", "admin/", "test/", "data/", "archive/", "temp/",
        "webdav/", "git/", ".git/", "svn/", ".svn/", "conf/", "etc/", "log/", "cgi-bin/",
        "docs/", "logs/", "config/", "assets/", "img/", "images/", "dump/", "sql/", "old/", "temp/"
    ]
    
    found_any = False
    for directory in common_directories:
        target_url = urljoin(primary_url, directory)
        log_console(f"Checking: {target_url}", "cyan")
        try:
            response = requests.get(target_url, timeout=7, verify=False)
            add_scanned_link(target_url, response.status_code, "Directory Check")

            if response.status_code == 200:
                if ("index of /" in response.text.lower() and (
                    "<title>index of" in response.text.lower() or
                    "parent directory" in response.text.lower() or
                    "<pre>" in response.text.lower() and ('href' in response.text.lower() or '<a ' in response.text.lower())
                )):
                    scan_results["open_index_directories"].append(target_url)
                    log_console(f"  [+] Open Directory Listing Found: {target_url}", "green")
                    found_any = True
                else:
                    log_console(f"  [~] Directory accessible (Status 200), but not an index listing: {target_url}", "yellow")
            else:
                log_console(f"  [-] Directory not accessible or no listing: {target_url} (Status: {response.status_code})", "red")
        except requests.exceptions.RequestException as e:
            log_console(f"  Error accessing {target_url}: {e}", "red")
            add_scanned_link(target_url, "Error", f"Directory Check Error: {type(e).__name__}")
    
    if not found_any:
        log_console("No open index directories found.", "green")

def check_sensitive_files(primary_url):
    log_console("Checking for sensitive files...", "blue")
    sensitive_files = [
        ".env", "database.sql", "changelog.txt", "config.php", "wp-config.php",
        "web.config", "sftp-config.json", ".git/config", ".bash_history", ".ssh/id_rsa",
        "access.log", "error.log", "config.json", "package.json", "docker-compose.yml",
        ".htaccess", "id_rsa.pub", "passwords.txt", "credentials.txt",
        "configuration.php", "README.md", "LICENSE.txt", "info.php",
        "dump.sql", "site.bak", "db.sql.zip", "credentials.zip", "secret.txt",
        "robots.txt.bak", "sitemap.xml.bak" # Added more file extensions to search
    ]
    
    found_any = False
    for s_file in sensitive_files:
        target_url = urljoin(primary_url, s_file)
        log_console(f"Checking: {target_url}", "cyan")
        try:
            response = requests.get(target_url, timeout=7, allow_redirects=False, verify=False)
            file_extension = os.path.splitext(s_file)[1] if '.' in s_file else None
            add_scanned_link(target_url, response.status_code, "Sensitive File Check", file_extension)

            if response.status_code == 200 and len(response.content) > 0:
                scan_results["accessible_sensitive_files"].append(target_url)
                log_console(f"  [+] Sensitive file accessible: {target_url} (Size: {len(response.content)} bytes)", "red")
                found_any = True
            elif response.status_code == 401 or response.status_code == 403:
                 log_console(f"  [~] File likely exists but access denied (status {response.status_code}): {target_url}", "yellow")
            else:
                log_console(f"  [-] File not found or no content: {target_url} (Status: {response.status_code})", "green")
        except requests.exceptions.RequestException as e:
            log_console(f"  Error accessing {target_url}: {e}", "red")
            add_scanned_link(target_url, "Error", f"Sensitive File Check Error: {type(e).__name__}", file_extension)
    
    if not found_any:
        log_console("No directly accessible sensitive files found.", "green")

def port_scan(ip_address):
    log_console(f"Starting port scan for {ip_address}...", "blue")
    if not ip_address:
        log_console("IP address not available for port scanning.", "red")
        return

    common_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
        143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
        5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 4899: "RAdmin",
        88: "Kerberos", 161: "SNMP", 5060: "SIP", 5061: "SIP-TLS",
        1723: "PPTP", 993: "IMAPS", 995: "POP3S" # Additional common ports
    }
    
    open_ports_count = 0
    sorted_ports = sorted(common_ports.keys())

    for port in sorted_ports:
        service_name = common_ports[port]
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        result_message = ""
        probe_result = "N/A"
        status_color = "red"

        try:
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                status = "Open"
                status_color = "green"
                open_ports_count += 1
                result_message = f"  [+] Port {port} ({service_name}) is Open."
                
                try:
                    sock.settimeout(1.0) 
                    
                    if port in [80, 443, 8080, 8443]:
                        sock.sendall(b"HEAD / HTTP/1.0\r\nHost: test.com\r\nUser-Agent: ReconScanner\r\nConnection: Close\r\n\r\n") 
                    elif port == 21:
                        sock.sendall(b"FEAT\r\n") 
                    elif port == 22:
                        pass # SSH banner usually sent on connect
                    elif port == 23:
                        pass
                    elif port == 25:
                        sock.sendall(b"HELO example.com\r\n")
                    elif port == 110:
                        sock.sendall(b"CAPA\r\n")
                    elif port == 143:
                        sock.sendall(b"a001 CAPABILITY\r\n")
                    elif port == 3306: # MySQL - send initial handshake for version grab
                        # Minimal MySQL client handshake - not a full protocol but might trigger version
                        # The MySQL protocol begins with a handshake packet where the server sends version, etc.
                        # Simple read might get something
                        pass # No initial client send needed to read server banner for MySQL

                    banner_raw = sock.recv(2048) 
                    if banner_raw:
                        # Try decoding as UTF-8 first, then fall back to Latin-1 or errors=ignore
                        try:
                            probe_result = banner_raw.decode('utf-8').strip().split('\n')[0]
                        except UnicodeDecodeError:
                            probe_result = banner_raw.decode('latin-1', errors='ignore').strip().split('\n')[0]

                        if not probe_result: probe_result = f"Received {len(banner_raw)} bytes (no clear banner line)."
                    else:
                        probe_result = "No data received from service."
                    
                except socket.timeout:
                    probe_result = "No banner received within timeout."
                except ConnectionResetError: 
                    probe_result = "Connection reset by remote host (common for restrictive firewalls or unexpected protocol)."
                except Exception as probe_e:
                    probe_result = f"Probe Error: {type(probe_e).__name__} - {probe_e}"
                
                log_console(f"{result_message} - Probe: {probe_result}", status_color)
            else:
                status = "Closed"
                status_color = "red"
                result_message = f"  [-] Port {port} ({service_name}) is Closed."
                log_console(result_message, status_color)

            scan_results["port_scan_results"].append({
                "port": port,
                "service": service_name,
                "status": status,
                "probe_result": probe_result
            })
        except socket.error as e:
            status = "Error"
            status_color = "red"
            result_message = f"  Error scanning port {port}: {e}"
            log_console(result_message, status_color)
            scan_results["port_scan_results"].append({
                "port": port,
                "service": service_name,
                "status": status,
                "probe_result": f"Scan Error: {e}"
            })
        finally:
            sock.close()
    
    if open_ports_count == 0:
        log_console("No open ports found.", "yellow")
    else:
        log_console(f"Scan complete. Found {open_ports_count} open ports.", "green")

def subdomain_enumeration(domain, ip_address):
    log_console(f"Starting subdomain enumeration for {domain}...", "blue")
    found_subdomains_set = set()
    
    # 1. Brute Force (Basic wordlist)
    log_console("  [*] Brute-forcing common subdomains...", "cyan")
    common_subdomains_wordlist = [
        "www", "mail", "ftp", "blog", "dev", "test", "webmail", "admin", "api", "vpn",
        "ns1", "ns2", "docs", "portal", "cdn", "shop", "status", "secure",
        "autodiscover", "webdisk", "cpanel", "whm", "jira", "confluence", "git",
        "m", "mobile", "owa", "exchange", "vps", "host", "forum", "wiki"
    ]
    
    for sub in common_subdomains_wordlist:
        sub_domain = f"{sub}.{domain}"
        try:
            sub_ip = socket.gethostbyname(sub_domain)
            if sub_ip:
                found_subdomains_set.add(sub_domain)
                log_console(f"    [+] Found (Brute Force): {sub_domain} ({sub_ip})", "green")
        except socket.gaierror:
            pass

    # 2. crt.sh Certificate Transparency Logs
    log_console("  [*] Checking crt.sh certificate transparency logs...", "cyan")
    try:
        crt_sh_url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(crt_sh_url, timeout=15, verify=False)
        add_scanned_link(crt_sh_url, response.status_code, "CRT.SH lookup")

        if response.status_code == 200:
            entries = response.json()
            initial_subdomain_count = len(found_subdomains_set)
            for entry in entries:
                if 'common_name' in entry:
                    cn = entry['common_name'].strip()
                    if cn.endswith(domain) and not cn.startswith("*."):
                        found_subdomains_set.add(cn)
                if 'name_value' in entry:
                    names = re.split(r'[\n,]', entry['name_value'])
                    for name in names:
                        name = name.strip()
                        if name.startswith("*."):
                            name = name[2:]
                        if name and name.endswith(domain) and name != domain:
                            found_subdomains_set.add(name)
            
            if len(found_subdomains_set) > initial_subdomain_count:
                log_console(f"    [+] Discovered {len(found_subdomains_set) - initial_subdomain_count} new subdomains via crt.sh.", "green")
            else:
                log_console("    [~] No new subdomains found via crt.sh.", "yellow")
        else:
            log_console(f"    [-] Failed to fetch crt.sh data (Status: {response.status_code})", "yellow")
    except requests.exceptions.RequestException as e:
        log_console(f"    Error querying crt.sh: {e}", "red")
    except ValueError as e: 
        log_console(f"    Error parsing crt.sh response: {e}", "red")

    # 3. robots.txt and sitemap.xml analysis
    log_console("  [*] Checking robots.txt and sitemap.xml for subdomains...", "cyan")
    base_url = scan_results["primary_url"] if scan_results["primary_url"] else f"http://{domain}/"
    initial_subdomain_count = len(found_subdomains_set)

    for path in ["robots.txt", "sitemap.xml", "sitemap_index.xml", "sitemap.xml.gz"]: 
        file_url = urljoin(base_url, path)
        try:
            response = requests.get(file_url, timeout=7, verify=False)
            add_scanned_link(file_url, response.status_code, f"{path} check")
            if response.status_code == 200:
                log_console(f"    [+] Found {path}: {file_url}", "green")
                urls_in_file = re.findall(r'https?://(?:[a-zA-Z0-9-]+\.)*'+re.escape(domain)+r'(?:[/][^"\' ]*)?', response.text, re.IGNORECASE)
                
                if path.endswith(('.xml', '.xml.gz')):
                    urls_in_file.extend(re.findall(r'<loc>(https?://[^<]+?'+re.escape(domain)+r'[^<]+)</loc>', response.text, re.IGNORECASE))

                for u in urls_in_file:
                    parsed_url = urlparse(u)
                    if parsed_url.hostname and parsed_url.hostname.endswith(domain) and parsed_url.hostname != domain:
                        found_subdomains_set.add(parsed_url.hostname)
            else:
                log_console(f"    [-] {path} not found or accessible (Status: {response.status_code})", "yellow")
        except requests.exceptions.RequestException as e:
            log_console(f"    Error accessing {file_url}: {e}", "red")
            add_scanned_link(file_url, "Error", f"{path} Check Error: {type(e).__name__}")
    
    if len(found_subdomains_set) > initial_subdomain_count:
        log_console(f"    [+] Discovered {len(found_subdomains_set) - initial_subdomain_count} new subdomains via robots.txt/sitemap.xml.", "green")
    else:
        log_console("    [~] No new subdomains found via robots.txt/sitemap.xml.", "yellow")

    # Virtual Host Scanning 
    log_console("  [*] Attempting basic Virtual Host scanning (via IP)...", "cyan")
    if ip_address:
        vhost_attempts = [f"{s}.{domain}" for s in common_subdomains_wordlist] + [domain]
        initial_subdomain_count = len(found_subdomains_set)
        
        for vhost in vhost_attempts:
            try:
                headers = {'Host': vhost, 'User-Agent': 'Mozilla/5.0/ReconScanner'}
                vhost_url = f"http://{ip_address}/" 
                response = requests.get(vhost_url, headers=headers, timeout=5, allow_redirects=True, verify=False)
                add_scanned_link(f"{vhost_url} (Host: {vhost})", response.status_code, "Virtual Host check")

                if response.status_code == 200 and len(response.content) > 100: 
                    if vhost.endswith(domain) and vhost not in found_subdomains_set:
                        found_subdomains_set.add(vhost)
                        log_console(f"    [+] Potential Virtual Host found: {vhost} (Status: {response.status_code})", "green")
            except requests.exceptions.RequestException:
                pass 
        if len(found_subdomains_set) > initial_subdomain_count:
            log_console(f"    [+] Discovered {len(found_subdomains_set) - initial_subdomain_count} new subdomains via VHost scan.", "green")
        else:
            log_console("    [~] No new subdomains found via VHost scan.", "yellow")

    # Reverse IP Lookup:
    log_console("  [*] Performing Reverse IP lookup (for co-hosted domains/PTR records)...", "cyan")
    if ip_address:
        try:
            hostname_info = socket.gethostbyaddr(ip_address)
            
            if hostname_info[0] and hostname_info[0].endswith(domain) and hostname_info[0] != domain:
                if hostname_info[0] not in found_subdomains_set:
                    found_subdomains_set.add(hostname_info[0])
                    log_console(f"    [+] Reverse IP revealed potential subdomain: {hostname_info[0]}", "green")
            
            for alias in hostname_info[1]:
                if alias and alias.endswith(domain) and alias != domain:
                    if alias not in found_subdomains_set:
                        found_subdomains_set.add(alias)
                        log_console(f"    [+] Reverse IP revealed potential subdomain (alias): {alias}", "green")

            if len(found_subdomains_set) == 0 and not (hostname_info[0] and hostname_info[0].endswith(domain)): 
                 log_console(f"    [~] No new subdomains found via reverse IP for {ip_address}.", "yellow")

        except socket.herror as e:
            log_console(f"    [-] No PTR record found for {ip_address} or host error: {e}", "yellow")
        except Exception as e:
            log_console(f"    Error in reverse IP lookup: {e}", "red")

    log_console("  [*] Note: DNS Zone Transfer attempts (AXFR) are rarely successful for secure domains. (Skipped)", "yellow")

    scan_results["found_subdomains"] = sorted(list(found_subdomains_set))
    if scan_results["found_subdomains"]:
        log_console(f"\nSubdomain enumeration complete. Found {len(scan_results['found_subdomains'])} unique subdomains:", "green")
        for sub in scan_results["found_subdomains"]:
            log_console(f"  - {sub}")
    else:
        log_console("No additional subdomains found.", "yellow")


# --- NEW SPIDER CODE INTEGRATION ---
from bs4 import BeautifulSoup

def _clean_spider_url(url):
    # Ignore mailto, javascript, tel, or file links
    if any(url.startswith(scheme) for scheme in ["mailto:", "javascript:", "tel:", "file:"]):
        return None
    return url.split("#")[0].strip() # Remove anchor links

def _spider_analyze_and_crawl(current_url, base_target_domain):
    """
    Analyzes a given URL and recursively crawls valid links within the base domain.
    Internal function for web_spider_scan.
    """
    if current_url in scan_results["spider_visited_urls"]:
        return
    
    # Check if the URL is within the target domain. This is critical for controlling scope.
    if urlparse(current_url).netloc != base_target_domain:
        # log_console(f"    [SKIP] Out of scope (domain mismatch): {current_url}", "yellow") # Too verbose
        return

    scan_results["spider_visited_urls"].add(current_url)
    
    try:
        log_console(f"    [Spider] Fetching: {current_url}", "cyan")
        # Use requests with verify=False
        res = requests.get(current_url, timeout=7, verify=False, allow_redirects=True)
        status_code = res.status_code
        
        # Add the processed URL to the general scanned_links report
        # Use res.url as it's the final URL after any redirects
        add_scanned_link(res.url, status_code, "Web Spider Link") 

        log_console(f"    {res.url} - {status_code}", "green" if status_code < 400 else ("yellow" if status_code < 500 else "red"))
        
        soup = BeautifulSoup(res.text, 'html.parser')

        # Detect forms on the page
        if soup.find("form"):
            log_console(f"      [!] Form detected on: {res.url}", "magenta")

        for link_tag in soup.find_all('a', href=True):
            raw_link = _clean_spider_url(link_tag['href'])
            if not raw_link:
                continue

            full_url = urljoin(res.url, raw_link) # Use the final redirected URL to correctly resolve relative paths
            
            # Further clean the resolved full URL (removes redundant # if any)
            full_url_cleaned = _clean_spider_url(full_url)
            if not full_url_cleaned:
                continue

            parsed_full_url = urlparse(full_url_cleaned)
            
            # Recursively crawl only links that are HTTP/S and within the target domain
            # Avoid re-crawling just hash fragments of the current page ('/index.html#section' vs '/index.html')
            if parsed_full_url.scheme in ["http", "https"] and parsed_full_url.netloc == base_target_domain and full_url_cleaned not in scan_results["spider_visited_urls"]:
                _spider_analyze_and_crawl(full_url_cleaned, base_target_domain)
                        
    except requests.exceptions.RequestException as e:
        log_console(f"    [Spider ERROR] {current_url}: {e}", "red")
        add_scanned_link(current_url, f"Error: {type(e).__name__}", "Web Spider Error")
    except Exception as e:
        log_console(f"    [Spider UNEXPECTED ERROR] {current_url}: {e}", "red")
        add_scanned_link(current_url, f"Error: {type(e).__name__}", "Web Spider Error")

def web_spider_scan(start_url):
    """
    Starts the web spider scan from the primary_url.
    """
    if not start_url:
        log_console("Primary URL not available for web spidering.", "yellow")
        return
        
    target_netloc = urlparse(start_url).netloc
    if not target_netloc:
        log_console(f"Could not determine netloc for spidering from {start_url}.", "red")
        return

    log_console(f"\n--- Starting Web Spider Scan for {target_netloc} ---", "blue")
    _spider_analyze_and_crawl(start_url, target_netloc)
    log_console(f"--- Web Spider Scan Completed. {len(scan_results['spider_visited_urls'])} unique URLs attempted/visited ---", "blue")

# --- End NEW SPIDER CODE INTEGRATION ---


def generate_html_report(domain):
    log_console(f"\nGenerating HTML report: {domain.replace('.', '_')}_scan_report.html...", "blue")
    report_filename = f"{domain.replace('.', '_')}_scan_report.html"

    console_log_html = "".join(f"{line}\n" for line in scan_results['console_log'])

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Scan Report - {domain}</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; margin: 20px; background-color: #f8f9fa; color: #333; }}
            .container {{ max-width: 960px; margin: 20px auto; background: #fff; padding: 30px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }}
            h1, h2, h3 {{ color: #0056b3; border-bottom: 1px solid #e0e0e0; padding-bottom: 8px; margin-top: 30px; }}
            h1 {{ text-align: center; color: #004085; font-size: 2.5em; }}
            h2 {{ font-size: 1.8em; }}
            pre {{ background-color: #eee; padding: 15px; border-radius: 8px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; border: 1px solid #ddd; font-family: 'Consolas', 'Monaco', monospace; }}
            ul {{ list-style: disc; padding-left: 25px; }}
            ul li {{ margin-bottom: 8px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.05); }}
            th, td {{ border: 1px solid #e9ecef; padding: 12px; text-align: left; }}
            th {{ background-color: #f2f2f2; font-weight: bold; color: #555; }}
            tr:nth-child(even) {{ background-color: #f9f9f9; }}
            tr:hover {{ background-color: #f1f1f1; }}
            .status-ok {{ color: green; font-weight: bold; }}
            .status-warn {{ color: orange; font-weight: bold; }}
            .status-fail {{ color: red; font-weight: bold; }}
            .section {{ margin-bottom: 35px; padding-top: 15px; }}
            .info-box {{ background-color: #e6f3ff; border: 1px solid #b3d9ff; border-left: 5px solid #007bff; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
            
            /* Console log specific colors (mapping to ANSI_COLORS keys) */
            .green {{ color: #28a745; }} 
            .red {{ color: #dc3545; }}    
            .blue {{ color: #007bff; }}   
            .yellow {{ color: #ffc107; }}  
            .cyan {{ color: #17a2b8; }}   
            .white {{ color: #333; }}     

            /* Styling for scrolling link box */
            .scanned-links-box {{ 
                max-height: 400px; /* Adjust height as needed */
                overflow-y: auto; 
                border: 1px solid #e0e0e0;
                border-radius: 5px;
                padding: 10px;
                background-color: #fcfcfc;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🌐 Security Scan Report for <span class="blue">{domain}</span></h1>
            <p class="info-box"><strong>Date of Scan:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
            <p class="info-box"><strong>Target Domain:</strong> {scan_results['target_domain']}</p>
            <p class="info-box"><strong>Resolved IP Address:</strong> {scan_results['target_ip'] if scan_results['target_ip'] else 'N/A'}</p>
            <p class="info-box"><strong>Primary URL Scanned:</strong> 
                <a href="{scan_results['primary_url']}" target="_blank">{scan_results['primary_url']}</a> 
            </p>

            <div class="section">
                <h2>📊 Detected Technologies</h2>
                <ul>
                    {("".join(f"<li>{tech}</li>" for tech in scan_results['detected_technologies']) if scan_results['detected_technologies'] else "<li>No specific technologies detected.</li>")}
                </ul>
            </div>

            <div class="section">
                <h2>📂 Open Index Directories</h2>
                <ul>
                    {("".join(f'<li><a href="{dir_url}" target="_blank">{dir_url}</a></li>' for dir_url in scan_results['open_index_directories']) if scan_results['open_index_directories'] else "<li>No open index directories found.</li>")}
                </ul>
            </div>

            <div class="section">
                <h2>🚨 Accessible Sensitive Files</h2>
                <ul>
                    {("".join(f'<li><a href="{file_url}" target="_blank"><span class="red">{file_url}</span></a></li>' for file_url in scan_results['accessible_sensitive_files']) if scan_results['accessible_sensitive_files'] else "<li>No directly accessible sensitive files found.</li>")}
                </ul>
            </div>

            <div class="section">
                <h2>🚪 Port Scan Results</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>Service</th>
                            <th>Status</th>
                            <th>Probe/Banner</th>
                        </tr>
                    </thead>
                    <tbody>
                        {("".join(f"""
                        <tr>
                            <td>{res['port']}</td>
                            <td>{res['service']}</td>
                            <td class="{("green" if res['status'] == "Open" else "red")}">{res['status']}</td>
                            <td><pre>{res['probe_result'] if res['probe_result'] else 'N/A'}</pre></td>
                        </tr>
                        """ for res in scan_results['port_scan_results']) if scan_results['port_scan_results'] else "<tr><td colspan='4'>No port scan results.</td></tr>")}
                    </tbody>
                </table>
            </div>

            <div class="section">
                <h2>🔎 Discovered Subdomains</h2>
                <ul>
                    {("".join(f'<li><a href="http://{subdomain}" target="_blank">{subdomain}</a></li>' for subdomain in scan_results['found_subdomains']) if scan_results['found_subdomains'] else "<li>No additional subdomains found.</li>")}
                </ul>
            </div>

            <div class="section">
                <h2>🔗 All Scanned Links (HTTP/HTTPS)</h2>
                <div class="scanned-links-box">
                    <table>
                        <thead>
                            <tr>
                                <th>URL</th>
                                <th>Status Code</th>
                                <th>Type</th>
                                <th>File Ext.</th>
                            </tr>
                        </thead>
                        <tbody>
                            {("".join(f"""
                            <tr>
                                <td><a href="{link['url'].split(' (Host: ')[0]}" target="_blank">{link['url']}</a></td>
                                <td class="{
                                    'green' if isinstance(link['status_code'], int) and 200 <= link['status_code'] < 400 
                                    else ('yellow' if isinstance(link['status_code'], int) and 400 <= link['status_code'] < 500
                                    else 'red')
                                }">{link['status_code']}</td>
                                <td>{link['type']}</td>
                                <td>{link.get('file_ext', 'N/A')}</td>
                            </tr>
                            """ for link in scan_results['scanned_links']) if scan_results['scanned_links'] else "<tr><td colspan='4'>No links scanned.</td></tr>")}
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="section">
                <h2>💻 Console Log</h2>
                <pre>{console_log_html}</pre>
            </div>

            <div class="section">
                <p>Report generated by a custom cybersecurity reconnaissance script.</p>
                <p><strong>Disclaimer:</strong> This tool is for educational and research purposes only. Using <code>verify=False</code> bypasses SSL/TLS certificate validation, which can expose your connection to Man-in-the-Middle (MitM) attacks. It's used here for broader reconnaissance where certificate validity might not be the primary concern. Do NOT use this in production environments or for sensitive data transfers. Direct "exploit testing" implies intrusive actions that should only be performed with explicit authorization and a full understanding of ethical and legal implications.</p>
            </div>
        </div>
    </body>
    </html>
    """

    try:
        with open(report_filename, "w", encoding="utf-8") as f:
            f.write(html_content)
        log_console(f"Report saved as {report_filename}", "green")
    except IOError as e:
        log_console(f"Error saving HTML report to {report_filename}: {e}", "red")

# --- Main Scan Orchestration ---
def main():
    target_domain_input = input("Enter target domain (e.g., example.com): ").strip().lower()
    if not target_domain_input:
        log_console("Domain cannot be empty. Exiting.", "red")
        return

    # Use the input domain directly, will derive netloc later for spidering
    scan_results["target_domain"] = target_domain_input
    
    log_console(f"\n--- Starting Scan for {target_domain_input} ({datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}) ---", "blue")

    # Step 1: Resolve domain
    ip_address = resolve_domain(target_domain_input)
    if not ip_address:
        log_console("Cannot proceed with scan without resolving IP address.", "red")
        return

    # Step 2: Try to Connect to the Website
    primary_response = connect_to_website(target_domain_input)
    primary_url = scan_results.get("primary_url") # Get the URL determined in connect_to_website

    if not primary_response or not primary_url:
        log_console("Could not establish a primary connection to the website. Skipping web-based checks (tech detection, directories, files).", "yellow")
        # Still continue with port scan and subdomain enumeration if possible
    else:
        # Step 3: Detect Website Technologies
        detect_technologies(primary_response)

        # Step 4: Check for Open Index Directories
        check_open_index_directories(primary_url)

        # Step 5: Check for Sensitive Files
        check_sensitive_files(primary_url)

    # Step 6: Port Scanning + Simple Exploit Testing (Service Probing)
    log_console("\nNote on Port Scanning: This feature performs service detection and banner grabbing. It does NOT execute exploits or perform invasive testing.", "yellow")
    port_scan(ip_address)

    # Step 7: Subdomain Enumeration
    subdomain_enumeration(target_domain_input, ip_address)

    # Step 8: Web Spider (New Feature) - Called at the very end as requested
    log_console("\n--- Starting Comprehensive Web Spidering ---", "blue")
    # Spider only if a primary URL was established
    if primary_url:
        web_spider_scan(primary_url)
    else:
        log_console("Skipping web spidering: No primary URL could be established.", "yellow")

    # Step 9: Generate Final HTML Report
    generate_html_report(target_domain_input)
    
    log_console(f"\n--- Scan for {target_domain_input} Completed ---", "blue")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log_console("\nScan interrupted by user. Attempting to generate partial report...", "yellow")
        generate_html_report(scan_results["target_domain"] if scan_results["target_domain"] else "partial_scan")
    except Exception as e:
        log_console(f"\nAn unhandled critical error occurred during scan: {e}", "red")
        import traceback
        log_console(traceback.format_exc(), "red")
        generate_html_report(scan_results["target_domain"] if scan_results["target_domain"] else "error_scan")
