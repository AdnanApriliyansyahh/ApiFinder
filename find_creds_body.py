#!/usr/bin/env python3
import re
import argparse
import requests
from collections import defaultdict

# Disable SSL warnings (for self-signed certificates)
requests.packages.urllib3.disable_warnings()

# Regex patterns for API keys & credentials
patterns = {
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Test Key": r"sk_test_[0-9a-zA-Z]{24}",
    "Slack Token": r"xox[baprs]-[0-9A-Za-z\-]+",
    "SendGrid API Key": r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
    "Github Token": r"ghp_[0-9a-zA-Z]{36}",
    "Gitlab Token": r"glpat-[0-9a-zA-Z\-_]{20}",
    "Telegram Bot Token": r"[0-9]{8,10}:AA[0-9A-Za-z\-_]{33}",
    "JWT": r"eyJ[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+",
    "Bearer Token": r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",
    "Generic API Key": r"api[_-]?key[\"'=:\s]+[A-Za-z0-9\-._~+/]{16,}",
}

def fetch_and_scan(url):
    creds_found = defaultdict(list)
    try:
        r = requests.get(url, timeout=10, verify=False)
        body = r.text
        for name, regex in patterns.items():
            matches = re.findall(regex, body)
            for m in matches:
                creds_found[name].append(m)
    except Exception as e:
        print(f"[!] Failed to fetch {url}: {e}")
    return creds_found

def main():
    parser = argparse.ArgumentParser(description="Find API keys/credentials inside response body of URLs")
    parser.add_argument("input", help="Input file (list of URLs, e.g., way.txt)")
    parser.add_argument("-o", "--output", default="api_body_creds.txt", help="Output file")
    args = parser.parse_args()

    with open(args.input, "r") as f:
        urls = [line.strip() for line in f if line.strip()]

    all_results = defaultdict(list)

    for url in urls:
        print(f"[*] Scanning {url}")
        results = fetch_and_scan(url)
        for name, matches in results.items():
            for m in matches:
                all_results[name].append((m, url))

    with open(args.output, "w") as out:
        if not all_results:
            out.write("No credentials found.\n")
        else:
            for name, entries in all_results.items():
                out.write(f"\n=== {name} ===\n")
                for cred, url in entries:
                    out.write(f"  Found: {cred}\n  URL:   {url}\n\n")

    print(f"\n[✓] Done! Results saved to {args.output}")

if __name__ == "__main__":
    main()