import requests
from bs4 import BeautifulSoup
import re
import os
from urllib.parse import urljoin, urlparse

def download_page(url):
    """Downloads the content of a web page and HTTP headers."""
    try:
        response = requests.get(url, timeout=30, allow_redirects=True)
        response.raise_for_status()
        content_type = response.headers.get('Content-Type', '')
        return response.text, content_type, response.url
    except requests.exceptions.RequestException as e:
        print(f"Error downloading page {url}: {e}")
        return None, None, None

def extract_emails(html_content, url):
    """Extracts email addresses and returns them with source URL."""
    emails = []
    if html_content:
        email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        for email in re.findall(email_pattern, html_content):
            emails.append((email, url))
    return emails

def extract_passwords(html_content, url):
    """Extracts potential passwords and returns them with context and source URL."""
    passwords = []
    if html_content:
        password_pattern = r"(password|hasło)[:=]\s*([a-zA-Z0-9\W]{8,})"
        for match in re.findall(password_pattern, html_content, re.IGNORECASE):
            passwords.append((match[0], match[1], url))
    return passwords

def find_alerts(html_content, url, keywords):
    """Finds keywords and returns alerts with context and source URL."""
    alerts = []
    if html_content:
        for keyword in keywords:
            if re.search(r'\b' + re.escape(keyword) + r'\b', html_content, re.IGNORECASE):
                match = re.search(r'(.{0,50}\b' + re.escape(keyword) + r'\b.{0,50})', html_content, re.IGNORECASE)
                context = match.group(1).strip() if match else ""
                alerts.append((keyword, context, url))
    return alerts

def find_interesting_flags(html_content, url):
    """Finds interesting OSINT flags and returns them with source URL."""
    flags = []
    if html_content:
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ipv6_pattern = r'([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4}::([0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){1}::([0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){2}::([0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){3}::([0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){4}::([0-9a-fA-F]{1,4}:){0,1}[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){5}::[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){6}::'
        onion_pattern = r'\b[a-z2-7]{16}\.onion\b'
        btc_pattern = r'\b(bc1|[13])[a-zA-Z0-9]{25,34}\b'
        eth_pattern = r'\b0x[a-fA-F0-9]{40}\b'
        login_pattern = re.compile(r'<input.*?type=["\']password["\'].*?>', re.IGNORECASE)
        social_media_domains = ["facebook.com", "twitter.com", "linkedin.com", "instagram.com", "youtube.com"]

        if re.search(ip_pattern, html_content):
            flags.append(("Found IPv4 address", url))
        if re.search(ipv6_pattern, html_content):
            flags.append(("Found IPv6 address", url))
        if re.search(onion_pattern, html_content):
            flags.append(("Found .onion link", url))
        if re.search(btc_pattern, html_content):
            flags.append(("Found Bitcoin address", url))
        if re.search(eth_pattern, html_content):
            flags.append(("Found Ethereum address", url))
        if login_pattern.search(html_content):
            flags.append(("!!!POTENTIAL LOGIN FORM FOUND!!!", url))
        soup = BeautifulSoup(html_content, 'html.parser')
        for link in soup.find_all('a', href=True):
            for domain in social_media_domains:
                if domain in link['href'].lower():
                    flags.append((f"Found link to {domain.split('.')[0].capitalize()}", url))
                    break
    return flags

def extract_links(html_content, base_url):
    """Extracts all links from the page within the same domain and identifies PDF links."""
    soup = BeautifulSoup(html_content, 'html.parser')
    links = set()
    pdf_links = []
    if html_content:
        parsed_base = urlparse(base_url)
        for link in soup.find_all('a', href=True):
            absolute_url = urljoin(base_url, link['href'])
            parsed_url = urlparse(absolute_url)
            if parsed_url.netloc == parsed_base.netloc:
                if absolute_url.lower().endswith('.pdf'):
                    pdf_links.append(absolute_url)
                else:
                    links.add(absolute_url)
    return links, pdf_links

def crawl_website(start_url, max_depth=2):
    """Crawls the website starting from the given URL."""
    visited = set()
    queue = [(start_url, 0)]
    all_data = {
        'emails': [],
        'passwords': [],
        'alerts': [],
        'flags': [],
        'pdf_links': []
    }
    keywords = ["leak", "passport", "database dump", "breached", "stolen data", "compromised", "exposed", "credentials", "account details", "ID card", "driver license", "national identity", "personal information", "credit card", "bank account", "payment details", "secret", "confidential", "private"]

    while queue:
        current_url, depth = queue.pop(0)
        if current_url in visited or depth > max_depth:
            continue
        visited.add(current_url)
        print(f"Crawling: {current_url} (Depth: {depth})")

        html_content, content_type, final_url = download_page(current_url)
        if html_content and 'text/html' in content_type:
            all_data['emails'].extend(extract_emails(html_content, final_url))
            all_data['passwords'].extend(extract_passwords(html_content, final_url))
            all_data['alerts'].extend(find_alerts(html_content, final_url, keywords))
            all_data['flags'].extend(find_interesting_flags(html_content, final_url))

            if depth < max_depth:
                links, pdf_links = extract_links(html_content, final_url)
                all_data['pdf_links'].extend([(link, final_url) for link in pdf_links])
                for link in links:
                    if link not in visited:
                        queue.append((link, depth + 1))
        elif final_url and final_url not in visited and final_url.lower().endswith('.pdf'):
            all_data['pdf_links'].append((final_url, current_url))
            visited.add(final_url) # Mark PDF as visited

    return all_data

def save_log(start_url, all_data):
    """Saves the collected data to a log.txt file."""
    filename = f"{urlparse(start_url).netloc}_crawl_log.txt"
    filepath = os.path.join(os.getcwd(), filename)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(f"Crawl started from: {start_url}\n\n")

        if all_data['emails']:
            f.write("+++EMAILS FOUND+++\n")
            for email, source_url in all_data['emails']:
                f.write(f"- {email} (Source: {source_url})\n")
            f.write("\n")

        if all_data['passwords']:
            f.write("***POTENTIAL PASSWORDS FOUND*** (Review carefully!)\n")
            for context, password, source_url in all_data['passwords']:
                f.write(f"- Context: {context}, Password: {password} (Source: {source_url})\n")
            f.write("\n")

        if all_data['alerts']:
            f.write("!!!ALERTS!!!\n")
            for keyword, context, source_url in all_data['alerts']:
                f.write(f"- Keyword: {keyword}, Context: {context} (Source: {source_url})\n")
            f.write("\n")
            if all_data['pdf_links']:
                f.write("- PDF Download Links Found:\n")
                for pdf_url, source_url in sorted(all_data['pdf_links']):
                    f.write(f"  - {pdf_url} (Linked from: {source_url})\n")
                f.write("\n")

        if all_data['flags']:
            f.write("$$$OSINT FLAGS FOUND$$$\n")
            for flag, source_url in sorted(all_data['flags']):
                f.write(f"- {flag} (Source: {source_url})\n")
            f.write("\n")

    print(f"Crawl data saved to {filepath}")

if __name__ == "__main__":
    start_url = input("Enter the starting website link to crawl: ")
    all_data = crawl_website(start_url)
    save_log(start_url, all_data)
