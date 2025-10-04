#!/usr/bin/env python3
"""
DeepCredScan — Advanced Secret & API Key Detector for Bug Bounty Recon

This script scans live endpoints or JS files for exposed credentials,
API keys, tokens, and secrets from hundreds of popular providers.

Author: yourname (2025)
License: MIT
"""

import re
import argparse
import aiohttp
import asyncio
from collections import defaultdict
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================================================================
#  EXTENDED GLOBAL CREDENTIAL REGEX COLLECTION (2025 EDITION)
# ================================================================
patterns = {
    # --- Cloud & Infrastructure ---
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth Token": r"ya29\.[0-9A-Za-z\-_]+",
    "Firebase Cloud Messaging Key": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    "Firebase Web API Key": r"[A-Za-z0-9\-_]{39}",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]",
    "AWS Session Token": r"IQ[A-Za-z0-9\/\+=]{270,600}",
    "Azure Storage Key": r"[A-Za-z0-9+\/=]{88}",
    "Azure SAS Token": r"sv=\d{4}-\d{2}-\d{2}&ss=[a-z]+&srt=[a-z]+&sp=[rwdlcup]+&se=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z&st=\d{4}-\d{2}-\d{2}",
    "Oracle Cloud API Key": r"ocid1\.tenancy\.[a-z0-9]+\.[a-z0-9]+\.[a-z0-9]+",
    "DigitalOcean Token": r"doo_v1_[A-Za-z0-9]{64}",
    "Linode API Token": r"linode_[a-zA-Z0-9]{64}",
    "Vercel Token": r"vc\.s[0-9a-zA-Z]{22}",
    "Render API Key": r"rnd_[A-Za-z0-9]{40}",
    "Netlify Token": r"nf_[A-Za-z0-9]{35,50}",
    "Cloudflare API Key": r"[A-Za-z0-9]{37}",
    "Cloudflare API Token": r"cf[a-zA-Z0-9\-_]{40,70}",
    "Fastly API Token": r"fastly-[A-Za-z0-9_-]{32}",
    "Vultr API Key": r"VULTR_[A-Za-z0-9]{30,60}",
    "OVH API Key": r"ovh-[A-Za-z0-9]{24,40}",
    "Hetzner API Token": r"hetzner-[A-Za-z0-9]{20,60}",
    "Supabase Key": r"sbp_[A-Za-z0-9_-]{40,60}",
    "PlanetScale Token": r"pscale_[A-Za-z0-9]{40,60}",
    "Railway Token": r"railway_[A-Za-z0-9]{60,80}",

    # --- AI / ML / NLP / LLM APIs ---
    "OpenAI API Key": r"sk-[A-Za-z0-9]{32,48}",
    "Anthropic API Key": r"sk-ant-[A-Za-z0-9]{40,60}",
    "Cohere API Key": r"cohere-[A-Za-z0-9]{32,60}",
    "HuggingFace API Token": r"hf_[A-Za-z0-9]{30,60}",
    "Replicate API Key": r"r8_[A-Za-z0-9]{32,48}",
    "Stability AI Key": r"sk-[A-Za-z0-9]{40,60}",
    "Gemini API Key": r"gsk_[A-Za-z0-9]{40,60}",
    "Perplexity AI Key": r"pxy_[A-Za-z0-9]{30,60}",
    "ElevenLabs API Key": r"eleven_[A-Za-z0-9]{32,48}",
    "AssemblyAI Token": r"aa_[A-Za-z0-9]{30,60}",
    "Deepgram Key": r"dg_[A-Za-z0-9]{30,60}",
    "Voiceflow API Key": r"vf_[A-Za-z0-9]{40,60}",

    # --- Payment & Finance ---
    "Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Restricted Key": r"rk_live_[0-9a-zA-Z]{24}",
    "Braintree Token": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "Adyen API Key": r"AQ[0-9a-zA-Z_-]{32}",
    "Square Token": r"sq0[a-z]{3,4}-[0-9A-Za-z\-_]{22,43}",
    "Razorpay Key": r"rzp_[A-Za-z0-9]{32}",
    "Paystack Key": r"pk_live_[A-Za-z0-9]{32}",
    "Flutterwave Key": r"FLWSECK-[A-Za-z0-9]{32}-X",
    "Coinbase Key": r"[A-Za-z0-9]{32,64}",
    "Binance Key": r"binance_[A-Za-z0-9]{32,64}",
    "Kraken API Key": r"kraken_[A-Za-z0-9]{32,64}",
    "Plaid API Key": r"plaid_[a-zA-Z0-9]{30,60}",

    # --- Developer / CI / SCM ---
    "GitHub Token": r"gh[pousr]_[0-9a-zA-Z]{36,64}",
    "GitLab Token": r"glpat-[0-9a-zA-Z\-_]{20,64}",
    "Bitbucket Token": r"x-token-auth:[0-9a-zA-Z]{24,64}",
    "NPM Token": r"npm_[A-Za-z0-9]{36,64}",
    "Docker Token": r"dhp_[A-Za-z0-9]{32,64}",
    "Snyk Token": r"snyk_[A-Za-z0-9\-_]{66}",
    "JFrog API Key": r"AKCp[0-9a-zA-Z]{50,80}",
    "Postman API Key": r"PMAK-[A-Za-z0-9\-]{64}",
    "Travis CI Token": r"travis_[A-Za-z0-9]{40}",
    "CircleCI Token": r"circleci-token-[A-Za-z0-9]{40}",
    "Drone CI Token": r"drone_[A-Za-z0-9]{32,64}",
    "Jenkins Token": r"jenkins_[A-Za-z0-9]{32,64}",

    # --- Messaging & Communication ---
    "Slack Token": r"xox[baprs]-[0-9A-Za-z\-]+",
    "Discord Token": r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}",
    "Telegram Bot Token": r"[0-9]{8,10}:AA[0-9A-Za-z\-_]{33}",
    "Twilio SID": r"AC[a-zA-Z0-9]{32}",
    "Twilio Auth Token": r"[a-f0-9]{32}",
    "Mattermost Token": r"matt-[A-Za-z0-9]{20,40}",
    "Zoom JWT": r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
    "WhatsApp Business Token": r"EAA[A-Za-z0-9]{100,200}",

    # --- Email & Notification ---
    "SendGrid API Key": r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "Postmark API Token": r"[0-9a-z]{25}-[0-9a-z]{10}-[0-9a-z]{25}",
    "Brevo (Sendinblue) API Key": r"xkeysib-[A-Za-z0-9]{64}",
    "Mailchimp Key": r"[0-9a-f]{32}-us[0-9]{1,2}",
    "Resend API Key": r"re_[A-Za-z0-9_-]{32,64}",

    # --- Databases & Backends ---
    "MongoDB URI": r"mongodb(\+srv)?:\/\/[a-zA-Z0-9:_@.\-\/?&=]+",
    "MySQL URI": r"mysql:\/\/[a-zA-Z0-9:_@.\-\/?&=]+",
    "PostgreSQL URI": r"postgres:\/\/[a-zA-Z0-9:_@.\-\/?&=]+",
    "Redis URI": r"redis:\/\/[a-zA-Z0-9:_@.\-\/?&=]+",
    "Elasticsearch URI": r"elastic:\/\/[a-zA-Z0-9:_@.\-\/?&=]+",
    "Cassandra URI": r"cassandra:\/\/[a-zA-Z0-9:_@.\-\/?&=]+",

    # --- Security & Auth ---
    "Okta Token": r"00[0-9a-zA-Z-_]{40}",
    "Auth0 Client Secret": r"[a-zA-Z0-9-_]{64}",
    "Firebase ID Token": r"eyJhbGciOiJSUzI1NiIsImtpZCI6Ij",
    "JWT": r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
    "Bearer Token": r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",
    "Basic Auth": r"Basic\s+[A-Za-z0-9=:_+/]{10,}",
    "API Secret": r"secret[_-]?key[\"'=:\s]+[A-Za-z0-9\-._~+/]{16,}",

    # --- Misc & Generic ---
    "Generic API Key": r"api[_-]?key[\"'=:\s]+[A-Za-z0-9\-._~+/]{16,}",
    "Access Token": r"access[_-]?token[\"'=:\s]+[A-Za-z0-9\-._~+/]{16,}",
    "Private Key": r"-----BEGIN (RSA|DSA|EC|PGP|OPENSSH) PRIVATE KEY-----",
    "SSH Private Key": r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "PEM Certificate": r"-----BEGIN CERTIFICATE-----",
    "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Twitter API Key": r"(?i)(twitter|twt)_api_(key|secret)[\"'=:\s]+[A-Za-z0-9\-._~+/]{16,}",
    "LinkedIn Token": r"AQED[A-Za-z0-9\-_]{30,60}",
    "Dropbox Access Token": r"sl\.[A-Za-z0-9\-_]{60,80}",
    "Spotify Access Token": r"BQ[A-Za-z0-9_-]{80,100}",
}

# ================================================================
#  ASYNC SCANNING ENGINE
# ================================================================
async def fetch(session, url):
    try:
        async with session.get(url, timeout=10, ssl=False) as resp:
            if resp.status == 200:
                return await resp.text()
    except Exception as e:
        print(f"[!] Failed to fetch {url}: {e}")
    return ""

async def scan_url(session, url):
    creds_found = defaultdict(list)
    body = await fetch(session, url)
    if not body:
        return creds_found

    for name, regex in patterns.items():
        matches = re.findall(regex, body)
        for match in matches:
            creds_found[name].append(match)
    return creds_found

async def main():
    parser = argparse.ArgumentParser(
        description="DeepCredScan — Advanced Bug Bounty Credential Finder"
    )
    parser.add_argument("input", help="Input file (list of URLs or endpoints)")
    parser.add_argument("-o", "--output", default="deepcreds.txt", help="Output file")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Concurrency level")
    args = parser.parse_args()

    with open(args.input, "r") as f:
        urls = [line.strip() for line in f if line.strip()]

    all_results = defaultdict(list)

    connector = aiohttp.TCPConnector(limit=args.threads, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [scan_url(session, url) for url in urls]
        results = await asyncio.gather(*tasks)

    for url, result in zip(urls, results):
        for name, matches in result.items():
            for m in matches:
                all_results[name].append((m, url))

    with open(args.output, "w") as out:
        if not all_results:
            out.write("No potential credentials found.\n")
        else:
            for name, entries in all_results.items():
                out.write(f"\n=== {name} ===\n")
                for cred, url in entries:
                    out.write(f"  Found: {cred}\n  URL:   {url}\n\n")

    print(f"\n[✓] Scan complete. Results saved to {args.output}")

if __name__ == "__main__":
    asyncio.run(main())