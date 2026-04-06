import asyncio
import httpx
import argparse
import os

# High-probability bucket suffixes/prefixes for corporate assets
WORDS = [
    "dev", "prod", "staging", "test", "assets", "public", "private", "backup",
    "internal", "admin", "client", "sql", "db", "logs", "archive", "storage",
    "cloud", "data", "static", "web", "media", "files", "temp", "secret"
]

# Cloud Provider Templates
PROVIDERS = {
    "aws": "https://{bucket}.s3.amazonaws.com",
    "gcp": "https://storage.googleapis.com/{bucket}",
    "azure": "https://{bucket}.blob.core.windows.net"
}

async def check_bucket(client, bucket_name, provider_name, url_template):
    url = url_template.format(bucket=bucket_name)
    try:
        # We use HEAD to save bandwidth and speed up the scan
        resp = await client.head(url, timeout=5.0)
        
        status = resp.status_code
        result = None

        if status == 200:
            result = f"[!!!] OPEN {provider_name.upper()}: {url}"
        elif status == 403:
            result = f"[!] PROTECTED {provider_name.upper()}: {url} (Authenticated access required)"
        
        return result
    except:
        return None

async def main():
    parser = argparse.ArgumentParser(description="Nebula Hunter: Advanced Multi-Cloud Bucket Finder")
    parser.add_argument("-k", "--keyword", required=True, help="Base keyword (e.g., 'tesla')")
    parser.add_argument("-o", "--output", help="Output filename")
    args = parser.parse_args()

    base = args.keyword.lower()
    output_file = args.output if args.output else f"buckets_{base}.txt"
    
    # Generate Permutations
    permutations = {base}
    for word in WORDS:
        permutations.add(f"{base}-{word}")
        permutations.add(f"{word}-{base}")
        permutations.add(f"{base}.{word}")
        permutations.add(f"{base}{word}")

    print(f"[*] Generated {len(permutations)} permutations. Scanning across AWS, GCP, and Azure...")

    tasks = []
    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        for bucket in permutations:
            for provider, template in PROVIDERS.items():
                tasks.append(check_bucket(client, bucket, provider, template))
        
        results = await asyncio.gather(*tasks)

    # Clean results and write to file
    findings = [r for r in results if r]
    
    with open(output_file, "w") as f:
        if findings:
            for hit in findings:
                print(hit)
                f.write(hit + "\n")
        else:
            print("[-] No buckets found. Try a different keyword or expand the wordlist.")

    print(f"\n[+] Scan complete. Findings saved to: {output_file}")

if __name__ == "__main__":
    asyncio.run(main())
