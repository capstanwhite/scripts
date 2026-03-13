#!/bin/bash

# ===== CONFIG =====
GOBIN="/home/kali/go/bin"


HTTPX="$GOBIN/httpx"
WAYBACK="$GOBIN/waybackurls"
GAU="$GOBIN/gau"
GF="$GOBIN/gf"

# ==================

domain=$1

if [ -z "$domain" ]; then
  echo "Usage: ./recon.sh example.com"
  exit 1
fi

echo "[+] Starting recon for $domain"

mkdir -p "$domain/gf"
cd "$domain" || exit

# ------------------
echo "[+] Enumerating subdomains..."
subfinder -d "$domain" -silent > subs.txt
assetfinder --subs-only "$domain" >> subs.txt
sort -u subs.txt -o subs.txt

# ------------------
echo "[+] Checking alive hosts..."
cat subs.txt | $HTTPX -silent > alive.txt

# ------------------
echo "[+] Collecting URLs from Wayback + GAU..."
cat alive.txt | $WAYBACK > urls_wayback.txt
cat alive.txt | $GAU --threads 50 > urls_gau.txt

cat urls_wayback.txt urls_gau.txt | sort -u | uro > urls.txt
rm urls_wayback.txt urls_gau.txt

# ------------------
echo "[+] Extracting JS files..."
grep -iE "\.js(\?|$)" urls.txt > js.txt

# ------------------
echo "[+] Extracting URLs with parameters..."
grep "=" urls.txt > params.txt

# ------------------
echo "[+] Running GF patterns..."
cat urls.txt | $GF xss > gf/xss.txt
cat urls.txt | $GF sqli > gf/sqli.txt
cat urls.txt | $GF lfi > gf/lfi.txt
cat urls.txt | $GF redirect > gf/redirect.txt
cat urls.txt | $GF ssrf > gf/ssrf.txt

# ------------------
echo "[✓] Recon completed successfully!"
echo "[✓] Results saved in ./$domain/"
