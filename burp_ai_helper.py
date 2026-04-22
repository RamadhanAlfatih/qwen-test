#!/usr/bin/env python3
"""
Burp Suite to AI Helper Tool
Helps security researchers format HTTP requests/responses and JS bundles for AI analysis.
"""

import sys
import re
import ssl
import urllib3

# Disable SSL warnings for self-signed certs often found in bug bounties
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import requests
except ImportError:
    print("Error: 'requests' library not found.")
    print("Please install it using: pip install requests")
    sys.exit(1)

def parse_raw_request(raw_data):
    """Parse raw HTTP request into components."""
    lines = raw_data.split('\n')
    if not lines:
        return None, None, {}
    
    # First line is method, path, version
    first_line = lines[0].strip()
    parts = first_line.split(' ')
    if len(parts) < 2:
        return None, None, {}
    
    method = parts[0]
    # Handle cases where URL might be absolute or relative
    url_path = parts[1]
    
    headers = {}
    body_start = -1
    
    # Parse headers
    for i, line in enumerate(lines[1:], 1):
        line = line.strip()
        if line == '':
            body_start = i + 1
            break
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip()] = value.strip()
    
    # Get body
    body = ''
    if body_start != -1 and body_start < len(lines):
        body = '\n'.join(lines[body_start:])
    
    return method, url_path, headers, body

def execute_request(method, url_path, headers, body):
    """Execute the HTTP request and return response details."""
    # Determine host
    host = headers.get('Host', '')
    if not host:
        print("Error: Host header missing in request.")
        return None
    
    # Determine protocol
    protocol = 'https'
    if 'X-Forwarded-Proto' in headers:
        protocol = headers['X-Forwarded-Proto']
    # Default to https, user can modify if needed
    
    full_url = f"{protocol}://{host}{url_path}"
    
    print(f"\n[*] Executing {method} request to {full_url}...")
    
    try:
        resp = requests.request(
            method=method,
            url=full_url,
            headers=headers,
            data=body.encode('utf-8') if body else None,
            allow_redirects=False,
            verify=False,  # Ignore SSL errors for testing
            timeout=30
        )
        
        return {
            'status_code': resp.status_code,
            'headers': dict(resp.headers),
            'body': resp.text,
            'url': resp.url
        }
    except Exception as e:
        print(f"[!] Error executing request: {e}")
        return None

def analyze_js_bundle(js_content):
    """Perform basic static analysis on JS bundle to find potential secrets."""
    findings = []
    
    patterns = {
        'AWS Access Key': r'(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
        'AWS Secret Key': r'(?i)aws(.{0,20})?(?-i)["\'][0-9a-zA-Z\/+]{40}["\']',
        'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
        'Private Key': r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
        'JWT Token': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
        'Generic Secret': r'(?i)(api[_-]?key|secret[_-]?key|password|passwd|pwd|auth[_-]?token|access[_-]?token)["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
        'Internal URL': r'https?://(?:internal|dev|staging|test|local|192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)[^\s"\'<>]+',
        'GitHub Token': r'gh[pousr]_[A-Za-z0-9_]{36,}',
        'Slack Token': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*',
        'Stripe Key': r'sk_live_[0-9a-zA-Z]{24}',
    }
    
    for name, pattern in patterns.items():
        matches = re.findall(pattern, js_content)
        if matches:
            findings.append({
                'type': name,
                'count': len(matches),
                'samples': list(set(matches))[:3]  # Show up to 3 unique samples
            })
    
    return findings

def format_http_for_ai(raw_request, response_data):
    """Format HTTP request/response pair for AI analysis."""
    output = []
    output.append("### HTTP Request/Response for AI Analysis")
    output.append("")
    output.append("#### Original Request:")
    output.append("```http")
    output.append(raw_request.strip())
    output.append("```")
    output.append("")
    
    if response_data:
        output.append("#### Actual Response:")
        output.append(f"**Status Code:** {response_data['status_code']}")
        output.append(f"**Final URL:** {response_data['url']}")
        output.append("")
        output.append("**Headers:**")
        output.append("```http")
        for key, value in response_data['headers'].items():
            output.append(f"{key}: {value}")
        output.append("```")
        output.append("")
        output.append("**Body:**")
        output.append("```")
        output.append(response_data['body'][:50000])  # Limit body size
        if len(response_data['body']) > 50000:
            output.append("\n[... truncated ...]")
        output.append("```")
    else:
        output.append("#### Response: [Request failed or not executed]")
    
    return '\n'.join(output)

def format_js_for_ai(js_content, findings):
    """Format JS bundle for AI analysis."""
    output = []
    output.append("### JavaScript Bundle Analysis for AI")
    output.append("")
    
    if findings:
        output.append("#### ⚠️ Automated Static Analysis Findings:")
        for finding in findings:
            output.append(f"- **{finding['type']}**: Found {finding['count']} occurrence(s)")
            for sample in finding['samples']:
                # Mask sensitive parts of the sample
                masked = sample[:10] + "..." if len(sample) > 10 else sample
                output.append(f"  - Sample: `{masked}`")
        output.append("")
        output.append("*Note: Verify these findings manually. False positives are common.*")
        output.append("")
    
    output.append("#### Full JavaScript Code:")
    output.append("```javascript")
    # Truncate if too large for context window
    if len(js_content) > 100000:
        output.append(js_content[:100000])
        output.append("\n// [... truncated due to size ...]")
    else:
        output.append(js_content)
    output.append("```")
    output.append("")
    output.append("#### Suggested AI Prompts:")
    output.append("- \"Analyze this JS bundle for authentication logic flaws.\"")
    output.append("- \"Identify all API endpoints and their parameters.\"")
    output.append("- \"Find any hardcoded secrets or tokens that shouldn't be client-side.\"")
    output.append("- \"Look for DOM-based XSS vulnerabilities.\"")
    output.append("- \"Identify potential IDOR or authorization bypass patterns.\"")
    
    return '\n'.join(output)

def get_multiline_input(prompt):
    """Get multiline input from user until they type END."""
    print(prompt)
    print("(Paste content, then type 'END' on a new line to finish):")
    lines = []
    while True:
        try:
            line = input()
            if line.strip().upper() == 'END':
                break
            lines.append(line)
        except EOFError:
            break
    return '\n'.join(lines)

def main():
    print("=" * 60)
    print("   Burp Suite to AI Helper Tool")
    print("   For Web Pentesting & Bug Bounty Hunting")
    print("=" * 60)
    print("")
    
    while True:
        print("\nSelect Mode:")
        print("1. HTTP Request/Response Analysis")
        print("2. JavaScript Bundle Analysis")
        print("3. Exit")
        
        choice = input("\nEnter choice (1-3): ").strip()
        
        if choice == '1':
            raw_request = get_multiline_input("Paste your raw HTTP request from Burp:")
            
            if not raw_request.strip():
                print("[!] Empty request. Skipping.")
                continue
            
            method, url_path, headers, body = parse_raw_request(raw_request)
            
            if not method:
                print("[!] Failed to parse request. Please check format.")
                continue
            
            # Ask if user wants to execute the request
            exec_choice = input("\nDo you want to execute this request to get live response? (y/n): ").strip().lower()
            
            response_data = None
            if exec_choice == 'y':
                response_data = execute_request(method, url_path, headers, body)
            else:
                print("[*] Skipping request execution. Formatting raw request only.")
            
            formatted_output = format_http_for_ai(raw_request, response_data)
            
            print("\n" + "=" * 60)
            print("FORMATTED OUTPUT (Copy this for AI):")
            print("=" * 60)
            print(formatted_output)
            print("=" * 60)
            
            # Save to file optionally
            save_choice = input("\nSave to file? (y/n): ").strip().lower()
            if save_choice == 'y':
                filename = f"burp_output_{int(__import__('time').time())}.txt"
                with open(filename, 'w') as f:
                    f.write(formatted_output)
                print(f"[+] Saved to {filename}")
        
        elif choice == '2':
            js_content = get_multiline_input("Paste your JavaScript bundle content:")
            
            if not js_content.strip():
                print("[!] Empty content. Skipping.")
                continue
            
            print("\n[*] Analyzing JS bundle for potential secrets...")
            findings = analyze_js_bundle(js_content)
            
            formatted_output = format_js_for_ai(js_content, findings)
            
            print("\n" + "=" * 60)
            print("FORMATTED OUTPUT (Copy this for AI):")
            print("=" * 60)
            print(formatted_output)
            print("=" * 60)
            
            # Save to file optionally
            save_choice = input("\nSave to file? (y/n): ").strip().lower()
            if save_choice == 'y':
                filename = f"js_analysis_{int(__import__('time').time())}.txt"
                with open(filename, 'w') as f:
                    f.write(formatted_output)
                print(f"[+] Saved to {filename}")
        
        elif choice == '3':
            print("\n[+] Exiting. Happy hunting!")
            break
        
        else:
            print("[!] Invalid choice. Please select 1, 2, or 3.")

if __name__ == "__main__":
    main()
