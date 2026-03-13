#!/usr/bin/env python3

import os
import re
import requests
from urllib.parse import urlparse

# ================= CONFIG =================
INPUT_FILE = "js.txt"
OUTPUT_DIR = "javascriptdata"
TIMEOUT = 15

HEADERS = {
    "User-Agent": "Mozilla/5.0 JS Pentest Intel Extractor"
}

# ================= REGEX INTEL =================
PATTERNS = {

    # ================= CRITICAL SECRETS =================
    "CRITICAL_SECRETS": [

        # Generic secrets
        r"(?i)(api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token|auth[_-]?token|private[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}['\"]",

        # JWT
        r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",

        # Bearer tokens
        r"(?i)bearer\s+[A-Za-z0-9\-\._~\+\/]+=*",

        # Authorization headers
        r"(?i)authorization['\"]?\s*[:=]\s*['\"][^'\"]+['\"]",
    ],


    # ================= CLOUD PROVIDER KEYS =================
    "CLOUD_KEYS": [

        # AWS
        r"AKIA[0-9A-Z]{16}",
        r"ASIA[0-9A-Z]{16}",
        r"(?i)aws(.{0,20})?(secret|access)?.{0,20}['\"][A-Za-z0-9\/+=]{40}['\"]",

        # Google
        r"AIza[0-9A-Za-z\-_]{35}",
        r"ya29\.[0-9A-Za-z\-_]+",

        # Firebase
        r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",

        # Azure
        r"(?i)azure(.{0,20})?(key|token|secret)['\"]?\s*[:=]\s*['\"][A-Za-z0-9\-_=]{20,}['\"]",
    ],


    # ================= PAYMENT / FINANCE =================
    "PAYMENT_KEYS": [

        # Stripe
        r"sk_live_[0-9a-zA-Z]{24}",
        r"pk_live_[0-9a-zA-Z]{24}",

        # PayPal
        r"(?i)paypal(.{0,20})?(client|secret)['\"]?\s*[:=]\s*['\"][A-Za-z0-9\-_]{20,}['\"]",

        # Square
        r"sq0atp-[0-9A-Za-z\-_]{22}",
        r"sq0csp-[0-9A-Za-z\-_]{43}",
    ],


    # ================= GIT / DEV PLATFORM TOKENS =================
    "DEV_TOKENS": [

        # GitHub
        r"ghp_[A-Za-z0-9]{36}",
        r"github_pat_[A-Za-z0-9_]{82}",
        r"gho_[A-Za-z0-9]{36}",
        r"ghu_[A-Za-z0-9]{36}",
        r"ghs_[A-Za-z0-9]{36}",
        r"ghr_[A-Za-z0-9]{36}",

        # GitLab
        r"glpat-[0-9a-zA-Z\-_]{20}",

        # Bitbucket
        r"(?i)bitbucket(.{0,20})?(token|key|secret)['\"]?\s*[:=]\s*['\"][A-Za-z0-9\-_]{20,}['\"]",
    ],


    # ================= MESSAGING / INTEGRATIONS =================
    "INTEGRATION_KEYS": [

        # Slack
        r"xox[baprs]-[0-9a-zA-Z\-]{10,48}",

        # Discord webhook
        r"https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9\-_]+",

        # Twilio
        r"SK[0-9a-fA-F]{32}",

        # Sendgrid
        r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",

        # Mailgun
        r"key-[0-9a-zA-Z]{32}",
    ],


    # ================= DATABASE CONNECTIONS =================
    "DATABASE_URLS": [

        r"mongodb(\+srv)?:\/\/[^\s\"']+",
        r"postgres:\/\/[^\s\"']+",
        r"mysql:\/\/[^\s\"']+",
        r"redis:\/\/[^\s\"']+",
        r"amqp:\/\/[^\s\"']+",
    ],


    # ================= STORAGE BUCKETS =================
    "STORAGE_BUCKETS": [

        r"https:\/\/[A-Za-z0-9\-\.]+\.s3\.amazonaws\.com",
        r"https:\/\/storage\.googleapis\.com\/[A-Za-z0-9\-\.]+",
        r"https:\/\/[A-Za-z0-9\-]+\.blob\.core\.windows\.net",
    ],


    # ================= PRIVATE KEYS =================
    "PRIVATE_KEYS": [

        r"-----BEGIN PRIVATE KEY-----",
        r"-----BEGIN RSA PRIVATE KEY-----",
        r"-----BEGIN OPENSSH PRIVATE KEY-----",
        r"-----BEGIN DSA PRIVATE KEY-----",
        r"-----BEGIN EC PRIVATE KEY-----",
        r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    ],


    # ================= AUTH / LOGIN CLUES =================
    "AUTH_FUNCTIONS": [

        r"function\s+(login|logout|signin|signup|auth|authorize|token|admin|debug)\w*",
        r"(login|logout|auth|authorize|token|admin)\s*=\s*function",
    ],


    # ================= API / ENDPOINT DISCOVERY =================
    "API_ENDPOINTS": [

        r"https?://[^\s\"'>]+",

        r"/api/[a-zA-Z0-9_/?=&\-.]+",
        r"/v[0-9]+/[a-zA-Z0-9_/?=&\-.]+",

        r"/(admin|internal|private|debug|auth|dev|test)[a-zA-Z0-9_/?=&\-.]*",

        r"/graphql",
        r"/graphiql",

        r"/oauth/[a-zA-Z0-9_/?=&\-.]*",
    ],


    # ================= SENSITIVE PARAMETERS =================
    "INTERESTING_PARAMS": [

        r"(?i)(isAdmin|admin|debug|test|dev|internal|role|access|privilege|root|superuser)\s*[:=]",
    ],


    # ================= EMAIL / PERSONAL DATA =================
    "PII_DATA": [

        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}",
        r"\+?[0-9][0-9\-\(\) ]{8,}[0-9]",
    ],


    # ================= COMMENTS / DEV NOTES =================
    "COMMENTS_TODOS": [

        r"//.*",
        r"/\*[\s\S]*?\*/",

        r"(?i)TODO:.*",
        r"(?i)FIXME:.*",
        r"(?i)DEBUG:.*",
        r"(?i)HACK:.*",
        r"(?i)TEMP:.*",
        r"(?i)NOTE:.*",
    ]
}


# ================= HELPERS =================
def safe_filename(url):
    name = urlparse(url).path.split("/")[-1] or "index.js"
    return re.sub(r"[^a-zA-Z0-9._-]", "_", name)

def fetch_js(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 200:
            return r.text
    except requests.RequestException:
        pass
    return None

def extract(content):
    results = {}
    for category, regexes in PATTERNS.items():
        matches = set()
        for rx in regexes:
            for m in re.findall(rx, content):
                if isinstance(m, tuple):
                    matches.add("".join(m))
                else:
                    matches.add(m)
        if matches:
            results[category] = sorted(matches)
    return results

# ================= MAIN =================
def main():
    if not os.path.exists(INPUT_FILE):
        print("[!] js.txt not found")
        return

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    with open(INPUT_FILE) as f:
        urls = [x.strip() for x in f if x.strip()]

    for url in urls:
        print(f"[+] Processing {url}")
        content = fetch_js(url)

        if not content:
            print(f"[-] Failed to fetch")
            continue

        findings = extract(content)
        if not findings:
            print("[i] No reportable intel found")
            continue

        outfile = os.path.join(OUTPUT_DIR, safe_filename(url) + ".report.txt")

        with open(outfile, "w", encoding="utf-8") as f:
            f.write(f"// Source JavaScript: {url}\n")
            f.write("// Generated by JS Pentest Intel Extractor\n\n")

            for category, items in findings.items():
                f.write(f"================ {category} ================\n")
                for item in items:
                    f.write(f"{item}\n")
                f.write("\n")

        print(f"[✓] Report saved → {outfile}")

if __name__ == "__main__":
    main()
