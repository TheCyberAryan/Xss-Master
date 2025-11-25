#!/usr/bin/env python3
"""
XSS Scanner v6 — Auto from Burp Request OR URL
Author: THECYBERARYAN helper

Features:
- You can paste:
  * One or more raw Burp HTTP requests (GET/POST, HTTP/1/HTTP/2)
  * OR one or more plain URLs (GET)
- Auto-detect URL, method, all parameters (query, form, JSON, multipart)
- Fuzz ALL parameters with payloads from payloads.txt
- Only prints reflected payloads (no noise)
- Detects basic reflection contexts (HTML, <script>, attribute, JS string)
- Suggests payload category based on context
- Saves JSON report: xss_report.json
"""

import sys
import re
import json
import urllib.parse
from typing import List, Dict, Any, Tuple, Optional
import httpx

BANNER = r"""
// THECYBERARYAN — XSS Reflection Scanner v6
"""

PAYLOAD_FILE = "/home/ravan/Documents/pendrive/xxs.txt"
REPORT_FILE = "xss_report.json"


def split_raw_requests(raw: str) -> List[str]:
    """Split multiple raw HTTP requests from Burp into individual blocks."""
    lines = raw.splitlines()
    indices = []
    for i, line in enumerate(lines):
        if re.match(r"^(GET|POST|PUT|DELETE|PATCH|OPTIONS)\s+.+", line):
            indices.append(i)
    requests = []
    for idx, start in enumerate(indices):
        end = indices[idx + 1] if idx + 1 < len(indices) else len(lines)
        block = "\n".join(lines[start:end]).strip()
        if block:
            requests.append(block)
    return requests


def parse_single_request(raw_req: str) -> Tuple[str, str, Dict[str, str], str]:
    """Parse a single raw HTTP request block into method, url, headers, body."""
    lines = raw_req.splitlines()
    request_line = lines[0]
    method, path, _ = request_line.split()

    headers: Dict[str, str] = {}
    body_lines: List[str] = []
    in_body = False

    for line in lines[1:]:
        if not in_body:
            if line.strip() == "":
                in_body = True
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        else:
            body_lines.append(line)
    body = "\n".join(body_lines)

    host = headers.get("host", "")
    # Guess scheme
    scheme = "https://"
    if path.startswith("http://") or path.startswith("https://"):
        url = path
    else:
        url = f"{scheme}{host}{path}"

    return method.upper(), url, headers, body


def extract_params(
    method: str,
    url: str,
    headers: Dict[str, str],
    body: str,
) -> List[Dict[str, Any]]:
    """
    Extract ALL parameters from query string, form, JSON, multipart.
    Returns list of dicts: {name, value, location}
    location: "query", "form", "json", "multipart"
    """
    params: List[Dict[str, Any]] = []

    # Query params
    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    for name, value in query_params:
        params.append({
            "name": name,
            "value": value,
            "location": "query",
        })

    # Body params
    ct = headers.get("content-type", "").lower()

    # JSON body
    if "application/json" in ct:
        try:
            data = json.loads(body or "{}")
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, (str, int, float)):
                        params.append({
                            "name": k,
                            "value": str(v),
                            "location": "json",
                        })
        except Exception:
            pass

    # Multipart form-data
    elif "multipart/form-data" in ct and "boundary=" in ct:
        boundary = ct.split("boundary=")[-1]
        boundary_bytes = f"--{boundary}"
        parts = body.split(boundary_bytes)
        for part in parts:
            if "Content-Disposition" not in part:
                continue
            name_match = re.search(r'name="([^"]+)"', part)
            if not name_match:
                continue
            name = name_match.group(1)
            # Value after blank line
            value = part.split("\r\n\r\n", 1)[-1].strip("\r\n-")
            params.append({
                "name": name,
                "value": value,
                "location": "multipart",
            })

    # URL-encoded or generic body
    elif body and "=" in body and method in ("POST", "PUT", "PATCH"):
        form_params = urllib.parse.parse_qsl(body, keep_blank_values=True)
        for name, value in form_params:
            params.append({
                "name": name,
                "value": value,
                "location": "form",
            })

    return params


def send_request(
    method: str,
    url: str,
    headers: Dict[str, str],
    body: Optional[str],
) -> Optional[httpx.Response]:
    """Send HTTP/2 request with browser-ish headers."""
    base_headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*",
    }
    # Merge but keep original content-type if present
    merged_headers = base_headers.copy()
    for k, v in headers.items():
        if k.lower() == "content-length":
            continue
        merged_headers[k] = v

    try:
        with httpx.Client(http2=True, verify=False, follow_redirects=True, timeout=20.0) as client:
            if method == "GET":
                return client.get(url, headers=merged_headers)
            else:
                return client.post(url, headers=merged_headers, content=body or "")
    except Exception as e:
        print(f"[!] Request error to {url}: {e}")
        return None


def detect_reflection(payload: str, text: str) -> Tuple[bool, Dict[str, bool]]:
    """Check if payload (or encoded variants) appears in the response + context flags."""
    details: Dict[str, bool] = {}

    raw_hit = payload in text
    url_enc = urllib.parse.quote(payload)
    url_hit = url_enc in text
    url2_hit = urllib.parse.quote(url_enc) in text
    lower_hit = payload.lower() in text.lower()

    details["raw"] = raw_hit
    details["url_encoded"] = url_hit
    details["double_url_encoded"] = url2_hit
    details["lowercase"] = lower_hit

    # Script context
    script_hit = bool(re.search(
        r"<script[^>]*>[^<]*" + re.escape(payload) + r"[^<]*</script>",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    ))
    details["script_context"] = script_hit

    # Attribute context
    attr_hit = bool(re.search(
        r'="[^"]*' + re.escape(payload) + r'[^"]*"',
        text,
        flags=re.IGNORECASE | re.DOTALL,
    ))
    details["attr_context"] = attr_hit

    # JS string context (simplified)
    js_hit = bool(re.search(
        r'["\'][^"\']*' + re.escape(payload) + r'[^"\']*["\']',
        text,
        flags=re.DOTALL,
    ))
    details["js_string_context"] = js_hit

    any_hit = any(details.values())
    return any_hit, details


def suggest_category(details: Dict[str, bool]) -> str:
    """Suggest payload family based on context."""
    if details.get("script_context") or details.get("js_string_context"):
        return "JS context (use JS-breaker payloads)"
    if details.get("attr_context"):
        return "Attribute context (use \" onxxx= payloads)"
    if details.get("raw") or details.get("url_encoded") or details.get("double_url_encoded"):
        return "HTML/URL context (basic XSS payloads)"
    return "Weak/partial reflection (needs manual review)"


def load_payloads(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def main():
    print(BANNER)
    print("Paste one or more raw Burp requests OR URLs, then press CTRL+D:\n")

    raw_all = sys.stdin.read().strip()
    if not raw_all:
        print("No input received.")
        return

    lines = [l.strip() for l in raw_all.splitlines() if l.strip()]
    first_line = lines[0]

    # Decide mode: HTTP request mode vs URL mode
    http_req_pattern = re.compile(r"^(GET|POST|PUT|DELETE|PATCH|OPTIONS)\s+.+HTTP/\d", re.IGNORECASE)
    url_mode = False

    if http_req_pattern.match(first_line):
        # Raw HTTP requests mode (Burp copy)
        requests_raw = split_raw_requests(raw_all)
    else:
        # URL mode: each non-empty line is a URL
        url_mode = True
        requests_raw = lines  # here each "request" is just a URL string

    try:
        payloads = load_payloads(PAYLOAD_FILE)
    except FileNotFoundError:
        print(f"[!] {PAYLOAD_FILE} not found. Create it with one payload per line.")
        return

    print(f"\n[*] Loaded {len(requests_raw)} item(s) from input.")
    print(f"[*] Loaded {len(payloads)} payload(s) from {PAYLOAD_FILE}.")
    print("\n=== REFLECTED PAYLOADS ===\n")

    report: Dict[str, Any] = {"requests": []}
    global_reflections = 0

    for ridx, raw_req in enumerate(requests_raw, start=1):

        if url_mode:
            # Treat as simple GET URL with no headers/body
            method = "GET"
            url = raw_req
            headers: Dict[str, str] = {}
            body = ""
        else:
            method, url, headers, body = parse_single_request(raw_req)

        params = extract_params(method, url, headers, body)

        if not params:
            print(f"[i] Request #{ridx}: no parameters found ({method} {url})")
            report["requests"].append({
                "id": ridx,
                "method": method,
                "url": url,
                "params": [],
            })
            continue

        req_entry = {
            "id": ridx,
            "method": method,
            "url": url,
            "params": [],
        }

        print(f"--- Request #{ridx}: {method} {url} ---")

        for p in params:
            pname = p["name"]
            ploc = p["location"]
            param_result = {
                "name": pname,
                "location": ploc,
                "reflections": [],
            }

            for payload in payloads:

                # Build fuzzed URL/body per param
                parsed = urllib.parse.urlparse(url)
                query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
                form_pairs = []
                json_data = None

                ct = headers.get("content-type", "").lower()

                if ploc == "query":
                    new_query = []
                    for k, v in query_pairs:
                        if k == pname:
                            new_query.append((k, payload))
                        else:
                            new_query.append((k, v))
                    new_query_str = urllib.parse.urlencode(new_query, doseq=True)
                    fuzz_url = urllib.parse.urlunparse(
                        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query_str, parsed.fragment)
                    )
                    fuzz_body = body

                elif ploc == "form":
                    form_pairs = urllib.parse.parse_qsl(body, keep_blank_values=True)
                    new_form = []
                    for k, v in form_pairs:
                        if k == pname:
                            new_form.append((k, payload))
                        else:
                            new_form.append((k, v))
                    fuzz_body = urllib.parse.urlencode(new_form, doseq=True)
                    fuzz_url = url

                elif ploc == "json" and "application/json" in ct:
                    try:
                        json_data = json.loads(body or "{}")
                        json_data[pname] = payload
                        fuzz_body = json.dumps(json_data)
                        fuzz_url = url
                    except Exception:
                        continue

                elif ploc == "multipart" and "multipart/form-data" in ct and "boundary=" in ct:
                    boundary = ct.split("boundary=")[-1]
                    parts = body.split(f"--{boundary}")
                    rebuilt = []
                    for part in parts:
                        if not part.strip() or "Content-Disposition" not in part:
                            rebuilt.append(part)
                            continue
                        name_match = re.search(r'name="([^"]+)"', part)
                        if not name_match:
                            rebuilt.append(part)
                            continue
                        name = name_match.group(1)
                        if name != pname:
                            rebuilt.append(part)
                            continue
                        # Replace value
                        head, sep, val = part.partition("\r\n\r\n")
                        new_part = head + sep + payload + "\r\n"
                        rebuilt.append(new_part)
                    fuzz_body = f"--{boundary}".join(rebuilt)
                    fuzz_url = url
                else:
                    # Unknown location type, skip
                    continue

                resp = send_request(method, fuzz_url, headers, fuzz_body if method != "GET" else None)
                if not resp:
                    continue

                hit, details = detect_reflection(payload, resp.text)
                if hit:
                    global_reflections += 1
                    cat = suggest_category(details)
                    ctxs = [k for k, v in details.items() if v]

                    print(f"[✔] R{ridx} param={pname} loc={ploc}")
                    print(f"     payload: {payload}")
                    print(f"     ctx: {', '.join(ctxs)}")
                    print(f"     hint: {cat}")

                    param_result["reflections"].append({
                        "payload": payload,
                        "contexts": ctxs,
                        "category": cat,
                    })

            if param_result["reflections"]:
                req_entry["params"].append(param_result)

        report["requests"].append(req_entry)

    # Save JSON report
    try:
        with open(REPORT_FILE, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] JSON report saved to {REPORT_FILE}")
    except Exception as e:
        print(f"[!] Failed to save JSON report: {e}")

    print(f"\n[+] Total reflected hits: {global_reflections}")
    print("Done.\n")


if __name__ == "__main__":
    main()
