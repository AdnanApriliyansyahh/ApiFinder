#!/usr/bin/env python3
import re
import argparse
import requests
from collections import defaultdict

# Disable SSL warnings (for self-signed certificates)
requests.packages.urllib3.disable_warnings()

patterns = {
    # Cloud Providers
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth": r"ya29\.[0-9A-Za-z\-_]+",
    "Firebase": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]",
    "Azure Storage Key": r"[A-Za-z0-9+\/=]{88}",
    "Heroku API Key": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",

    # Payment
    "Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Test Key": r"sk_test_[0-9a-zA-Z]{24}",
    "PayPal Braintree": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "Square Access Token": r"sq0atp-[0-9A-Za-z\-_]{22}",
    "Square OAuth Secret": r"sq0csp-[0-9A-Za-z\-_]{43}",
    "Adyen API Key": r"AQ[0-9a-zA-Z_-]{32}",

    # Messaging / Communication
    "Slack Token": r"xox[baprs]-[0-9A-Za-z\-]+",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "Twilio SID": r"AC[a-zA-Z0-9]{32}",
    "Telegram Bot Token": r"[0-9]{8,10}:AA[0-9A-Za-z\-_]{33}",
    "Discord Token": r"ODI[0-9A-Za-z]{20,30}\.[0-9A-Za-z_-]{6,7}\.[0-9A-Za-z_-]{27}",

    # Developer Platforms
    "Github Token": r"ghp_[0-9a-zA-Z]{36}",
    "Gitlab Token": r"glpat-[0-9a-zA-Z\-_]{20}",
    "Bitbucket Key": r"x-token-auth:[0-9a-zA-Z]{24}",

    # Email / Notifications
    "SendGrid API Key": r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "Postmark API Token": r"[0-9a-z]{25}-[0-9a-z]{10}-[0-9a-z]{25}",

    # Authentication / Security
    "Okta Token": r"00[0-9a-zA-Z-_]{40}",
    "Auth0 Client Secret": r"[a-zA-Z0-9-_]{64}",
    "Firebase Web API Key": r"[A-Za-z0-9\-_]{39}",
    "JWT": r"eyJ[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+",
    "Bearer Token": r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",

    # Database
    "MongoDB Connection String": r"mongodb\+srv:\/\/[a-zA-Z0-9:_@.\-\/?&=]+",
    "MySQL Connection String": r"mysql:\/\/[a-zA-Z0-9:_@.\-\/?&=]+",
    "Postgres Connection String": r"postgres:\/\/[a-zA-Z0-9:_@.\-\/?&=]+",
    "Redis Connection String": r"redis:\/\/[a-zA-Z0-9:_@.\-\/?&=]+",

    # Generic
    "Generic API Key": r"api[_-]?key[\"'=:\s]+[A-Za-z0-9\-._~+/]{16,}",
    "Private Key": r"-----BEGIN (RSA|DSA|EC|PGP|OPENSSH) PRIVATE KEY-----",
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
    parser = argparse.ArgumentParser()
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
