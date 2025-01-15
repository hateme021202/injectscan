import requests
import re
import socket
from datetime import datetime

# Function to validate and format the URL
def validate_url(url):
    if not url.startswith(('http://', 'https://')):
        if url.startswith('www.'):
            url = 'https://' + url
        else:
            url = 'https://' + url
    return url

# Function to get the IP address from the URL
def get_ip_address(url):
    try:
        hostname = url.split("//")[-1].split("/")[0]
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror:
        return "Unable to resolve IP"

# Function to check for XSS vulnerabilities (with more specific checks)
def check_xss(url):
    xss_patterns = [
        'javascript:',
        'onerror=', 
        'onload=',
        'document.cookie',  # Checking for potential XSS payloads that manipulate cookies
    ]
    try:
        response = requests.get(url)
        for pattern in xss_patterns:
            if pattern in response.text.lower():
                return "Vulnerable", f"XSS detected due to presence of potentially dangerous JavaScript patterns like '{pattern}', which can be exploited to inject malicious scripts.\n\nExample Source HTML:\n{response.text[:500]}..."
        return "Not Vulnerable", "No XSS vulnerabilities detected. The website seems to sanitize user inputs properly."
    except Exception as e:
        print(f"Error checking XSS: {e}")
        return "Possible Vulnerable", "Error checking XSS."

# Function to check for SQL Injection vulnerabilities (with detailed explanation)
def check_sql_injection(url):
    sql_injection_patterns = ["' OR 1=1", '" OR 1=1', "'--", '"--', 'OR 1=1']
    try:
        response = requests.get(url)
        for pattern in sql_injection_patterns:
            if pattern in response.text:
                return "Vulnerable", (
                    f"SQL Injection detected due to presence of suspicious patterns like '{pattern}'. This indicates that the website is not properly sanitizing "
                    "user input, which can allow attackers to execute arbitrary SQL commands, leading to data leakage, unauthorized access, or even deletion or modification of data.\n\n"
                    "Example Request: {url}?id={pattern}\n\nExample Response:\n{response.text[:500]}..."
                )
        return "Not Vulnerable", "No SQL Injection vulnerabilities detected. The website appears to have input validation or parameterized queries in place."
    except Exception as e:
        print(f"Error checking SQL Injection: {e}")
        return "Possible Vulnerable", "Error checking SQL Injection."

# Function to check for CSRF vulnerabilities (enhanced check for tokens, cookies, and headers)
def check_csrf(url):
    try:
        response = requests.get(url)
        
        csrf_token_in_forms = False
        csrf_cookie_protection = False
        csrf_header_protection = False

        # Check for forms with a CSRF token
        form_csrf_check = re.findall(r'<form.*?action=["\']([^"\']+)["\'].*?>.*?<input.*?name=["\']csrf(?:_token)?["\'].*?>', response.text, re.IGNORECASE)
        if form_csrf_check:
            csrf_token_in_forms = True

        # Check for CSRF-related cookies (SameSite attribute)
        cookies = response.cookies
        for cookie in cookies:
            if 'SameSite' in cookie and (cookie['SameSite'].lower() == 'strict' or cookie['SameSite'].lower() == 'lax'):
                csrf_cookie_protection = True
                break

        # Check if any CSRF protection headers are present in the response (like X-Csrf-Token)
        if 'X-Csrf-Token' in response.headers or 'csrf-token' in response.headers:
            csrf_header_protection = True
        
        # Based on the findings, classify the CSRF protection
        if csrf_token_in_forms or csrf_cookie_protection or csrf_header_protection:
            return "Not Vulnerable", "No CSRF vulnerabilities detected. The website appears to have implemented CSRF protection via forms, cookies, or headers."
        else:
            return "Vulnerable", (
                "CSRF vulnerability detected: The website does not appear to have CSRF protection mechanisms such as tokens in forms, SameSite cookies, or headers.\n\n"
                "A potential attacker could forge a request from an authenticated user without their knowledge.\n\nExample Attack:\n"
                "An attacker could craft a malicious HTML form to submit a request that transfers money from the victim’s account to the attacker's account.\n"
                "This attack could be successful if the victim is authenticated and the website lacks CSRF protection."
            )
    except Exception as e:
        print(f"Error checking CSRF: {e}")
        return "Possible Vulnerable", "Error checking CSRF."

# Function to check for Path Traversal vulnerability with advanced payloads
def check_path_traversal(url):
    # Advanced payloads for path traversal attacks
    traversal_payloads = [
        "../../../../etc/passwd",  # Unix/Linux file example
        "..%2F..%2F..%2Fetc%2Fpasswd",  # URL-encoded version
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",  # Windows file example
        "%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd",  # Double URL-encoded payload
        "%252E%252E%252F%252E%252E%252F%252E%252E%252Fetc%252Fpasswd",  # Triple URL-encoded payload
        "../../../../../../var/www/html/index.html",  # Web directory example
        "%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fweb%2Findex.html",  # URL-encoded web directory path
    ]
    
    for payload in traversal_payloads:
        test_url = f"{url}/{payload}"
        try:
            response = requests.get(test_url)
            if response.status_code == 200:
                return "Vulnerable", f"Path Traversal detected. The server allows path traversal through the following payload: '{payload}'. This could allow an attacker to access sensitive files on the server.\n\nExample Request: {test_url}\n\nExample Response: {response.text[:500]}..."
        except Exception as e:
            print(f"Error checking Path Traversal: {e}")
            return "Possible Vulnerable", "Error checking Path Traversal."
    
    return "Not Vulnerable", "No Path Traversal vulnerabilities detected. The server seems to properly handle file path inputs."

# Function to get the user's location (latitude, longitude, state, country) based on their IP address
def get_ip_location():
    try:
        # Use ipinfo.io API to get geolocation based on the user's public IP
        response = requests.get("http://ipinfo.io/json")
        data = response.json()
        
        # Extracting latitude, longitude, country, and region (state)
        location = data.get('loc', '').split(',')
        latitude = location[0] if location else 'Unknown'
        longitude = location[1] if location else 'Unknown'
        country = data.get('country', 'Unknown')
        state = data.get('region', 'Unknown')
        
        return latitude, longitude, state, country
    except Exception as e:
        print(f"Error fetching location: {e}")
        return 'Unknown', 'Unknown', 'Unknown', 'Unknown'

# Function to generate a vulnerability report with explanations
def generate_report(url, xss, xss_explanation, sql_injection, sql_explanation, csrf, csrf_explanation, path_traversal, path_explanation, ip_address):
    report = {}
    report['URL'] = url
    report['IP Address'] = ip_address
    report['DateTimeScan'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    latitude, longitude, state, country = get_ip_location()
    report['Location'] = f"Latitude: {latitude}, Longitude: {longitude}, State: {state}, Country: {country}"
    
    report['LogScan'] = 'Scanning completed successfully.'
    report['Vulnerabilities'] = {
        'XSS': xss,
        'SQL Injection': sql_injection,
        'CSRF': csrf,
        'Path Traversal': path_traversal
    }
    report['Explanations'] = {
        'XSS': xss_explanation,
        'SQL Injection': sql_explanation,
        'CSRF': csrf_explanation,
        'Path Traversal': path_explanation
    }
    return report

# Function to print the results in a nice format
def print_report(report):
    print(f"\nScan Report:")
    print(f"URL: {report['URL']}")
    print(f"IP Address: {report['IP Address']}")
    print(f"Date and Time of Scan: {report['DateTimeScan']}")
    print(f"Location: {report['Location']}")
    print(f"Log: {report['LogScan']}")
    
    # Print vulnerabilities in a table format
    print("\nVulnerabilities Detected:")
    print(f"{'Vulnerability':<20} {'Status':<20}")
    print(f"{'='*50}")
    
    for vuln, status in report['Vulnerabilities'].items():
        print(f"{vuln:<20} {status:<20}")
    
    print(f"{'='*50}\n")
    
    # Provide detailed explanations in a nicely formatted way
    print(f"Explanations:")
    
    for vuln, explanation in report['Explanations'].items():
        print(f"\n{vuln} Explanation:")
        print(f"{'-'*50}")
        print(f"{explanation}")
        print(f"{'='*50}\n")

# Main function to scan and generate report
def scan_url():
    url = input("Please paste a URL to scan (with or without 'https://'): ").strip()
    url = validate_url(url)

    print(f"Scanning URL: {url}")
    
    # Get the IP address of the URL
    ip_address = get_ip_address(url)

    # Check for vulnerabilities and get detailed explanations
    xss, xss_explanation = check_xss(url)
    sql_injection, sql_explanation = check_sql_injection(url)
    csrf, csrf_explanation = check_csrf(url)
    path_traversal, path_explanation = check_path_traversal(url)

    # Generate the report
    report = generate_report(url, xss, xss_explanation, sql_injection, sql_explanation, csrf, csrf_explanation, path_traversal, path_explanation, ip_address)

    # Display the report
    print_report(report)

# Run the script
if __name__ == "__main__":
    scan_url()
