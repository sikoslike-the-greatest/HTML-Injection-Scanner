#!/usr/bin/env python3
"""
HTML Injection Scanner

Discovers parameters from URL query strings, HTML name= attributes,
and custom wordlists. Substitutes a payload into each parameter and
checks if a marker string is reflected in the response.

Usage:
  python3 html-inject-scan.py -u https://example.com/page
  python3 html-inject-scan.py -l urls.txt -p '"><zxcasd>' -m '<zxcasd>'
  python3 html-inject-scan.py -l urls.txt -w params.txt --cookie "SESSION=abc"
  python3 html-inject-scan.py -l urls.txt --header "Authorization: Bearer tok" --auto
"""

import argparse
import sys
import re
import warnings
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

warnings.simplefilter("ignore", InsecureRequestWarning)

C_RESET = "\033[0m"
C_RED = "\033[91m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_CYAN = "\033[96m"
C_DIM = "\033[90m"
C_BOLD = "\033[1m"

DEFAULT_PAYLOAD = '\'"><zxcasd>'
DEFAULT_MARKER = "<zxcasd>"
DEFAULT_EXTRA_PARAMS = [
    "bankId", "bankName", "balanceSum", "birthday", "sex",
    "objectTypeId", "coupon", "admitadUid", "clickId", "subId",
    "saleChannelIsn", "curatorIsn", "agentIsn", "bankStringCode",
    "advertiseUid", "utmCampaign", "utmContent", "utmMedium",
    "utmSource", "utmTerm", "workleUid", "subAgent",
    "sub_id", "click_id", "utm_source", "utm_medium", "utm_campaign",
    "utm_content", "utm_term", "ref", "redirect", "url", "next",
    "return", "callback", "search", "q", "query", "page", "id",
]

SCAN_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"


def banner():
    print(f"""
{C_CYAN}{C_BOLD}  ╦ ╦╔╦╗╔╦╗╦    ╦╔╗╔ ╦╔═╗╔═╗╔╦╗  ╔═╗╔═╗╔═╗╔╗╔
  ╠═╣ ║ ║║║║    ║║║║ ║║╣ ║   ║   ╚═╗║  ╠═╣║║║
  ╩ ╩ ╩ ╩ ╩╩═╝  ╩╝╚╝╚╝╚═╝╚═╝ ╩   ╚═╝╚═╝╩ ╩╝╚╝{C_RESET}
{C_DIM}  HTML Injection / Reflected XSS parameter scanner{C_RESET}
""")


def build_session(headers_list, cookies_str, proxy):
    s = requests.Session()
    s.headers["User-Agent"] = SCAN_UA
    s.verify = False

    if headers_list:
        for h in headers_list:
            k, _, v = h.partition(":")
            s.headers[k.strip()] = v.strip()

    if cookies_str:
        for pair in cookies_str.split(";"):
            k, _, v = pair.partition("=")
            s.cookies.set(k.strip(), v.strip())

    if proxy:
        s.proxies = {"http": proxy, "https": proxy}

    return s


def extract_params_from_url(url):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    return list(qs.keys())


def extract_params_from_html(session, url, mode="input"):
    try:
        resp = session.get(url, timeout=15, allow_redirects=True)
        html = resp.text
    except Exception:
        return []

    if mode == "input":
        pattern = r'<input[^>]+name=["\']?([^"\'\s>]+)'
    else:
        pattern = r'name=["\']?([^"\'\s>]+)'

    names = re.findall(pattern, html, re.IGNORECASE)
    return list(dict.fromkeys(names))


def load_wordlist(path):
    try:
        with open(path) as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{C_RED}[!] Wordlist not found: {path}{C_RESET}")
        return []


def interactive_select(params, source_label):
    if not params:
        return []

    print(f"\n{C_CYAN}[{source_label}] Found {len(params)} params:{C_RESET}")
    for i, p in enumerate(params):
        print(f"  {C_DIM}{i:3d}{C_RESET} {p}")

    print(f"\n{C_YELLOW}  a{C_RESET} = select all, {C_YELLOW}n{C_RESET} = select none, "
          f"{C_YELLOW}0,1,5-10{C_RESET} = pick by index")
    choice = input(f"{C_CYAN}  > {C_RESET}").strip().lower()

    if choice == "a" or choice == "":
        return params[:]
    if choice == "n":
        return []

    selected = set()
    for part in choice.split(","):
        part = part.strip()
        if "-" in part:
            lo, _, hi = part.partition("-")
            try:
                for x in range(int(lo), int(hi) + 1):
                    if 0 <= x < len(params):
                        selected.add(x)
            except ValueError:
                pass
        else:
            try:
                idx = int(part)
                if 0 <= idx < len(params):
                    selected.add(idx)
            except ValueError:
                pass

    return [params[i] for i in sorted(selected)]


def test_reflection(session, base_url, param_name, payload, marker, method="GET"):
    parsed = urlparse(base_url)
    existing_qs = parse_qs(parsed.query, keep_blank_values=True)
    existing_qs[param_name] = [payload]
    new_query = urlencode(existing_qs, doseq=True)
    test_url = urlunparse(parsed._replace(query=new_query))

    try:
        if method.upper() == "GET":
            resp = session.get(test_url, timeout=15, allow_redirects=True)
        else:
            clean_url = urlunparse(parsed._replace(query=""))
            resp = session.post(clean_url, data=existing_qs, timeout=15, allow_redirects=True)

        reflected = marker in resp.text
        return {
            "url": test_url,
            "param": param_name,
            "status": resp.status_code,
            "reflected": reflected,
            "length": len(resp.text),
        }
    except Exception as e:
        return {
            "url": test_url,
            "param": param_name,
            "status": 0,
            "reflected": False,
            "length": 0,
            "error": str(e),
        }


def scan_url(session, url, all_params, payload, marker, method, threads, delay):
    parsed = urlparse(url)
    base_label = parsed.netloc + parsed.path
    print(f"\n{C_BOLD}[*] Scanning {C_CYAN}{base_label}{C_RESET} "
          f"({len(all_params)} params, method={method})")

    hits = []

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {}
        for p in all_params:
            f = pool.submit(test_reflection, session, url, p, payload, marker, method)
            futures[f] = p

        for f in as_completed(futures):
            r = f.result()
            status_color = C_GREEN if 200 <= r["status"] < 300 else C_YELLOW if 300 <= r["status"] < 400 else C_RED
            if r["reflected"]:
                print(f"  {C_RED}{C_BOLD}[REFLECTED]{C_RESET} {r['param']} "
                      f"— {status_color}{r['status']}{C_RESET} ({r['length']} bytes)")
                hits.append(r)
            else:
                print(f"  {C_DIM}[ ] {r['param']} — {r['status']} ({r['length']}){C_RESET}")

    return hits


def main():
    banner()

    parser = argparse.ArgumentParser(description="HTML Injection Scanner")
    parser.add_argument("-u", "--url", help="Single target URL")
    parser.add_argument("-l", "--list", help="File with list of URLs")
    parser.add_argument("-p", "--payload", default=DEFAULT_PAYLOAD, help="Injection payload")
    parser.add_argument("-m", "--marker", default=DEFAULT_MARKER,
                        help="Substring to search for in response (default: domain from payload)")
    parser.add_argument("-w", "--wordlist", help="Custom parameter wordlist file")
    parser.add_argument("--extra", default=",".join(DEFAULT_EXTRA_PARAMS),
                        help="Comma-separated extra param names")
    parser.add_argument("--header", action="append", help="Custom header (repeatable): 'Name: value'")
    parser.add_argument("--cookie", help="Cookie string: 'name=val; name2=val2'")
    parser.add_argument("--proxy", help="HTTP proxy: http://127.0.0.1:8080")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"], help="HTTP method")
    parser.add_argument("--threads", type=int, default=5, help="Concurrent requests per URL")
    parser.add_argument("--delay", type=float, default=0, help="Delay between requests (sec)")
    parser.add_argument("--mode", default="input", choices=["input", "all"],
                        help="HTML scan mode: 'input' = only <input name=>, 'all' = any tag with name=")
    parser.add_argument("--auto", action="store_true",
                        help="Non-interactive: auto-select all discovered params")
    parser.add_argument("--no-html-scan", action="store_true",
                        help="Skip fetching page to discover HTML name= attributes")
    parser.add_argument("-o", "--output", help="Save reflected hits to file")

    args = parser.parse_args()

    urls = []
    if args.url:
        urls.append(args.url)
    if args.list:
        urls.extend(load_wordlist(args.list))
    if not urls:
        parser.print_help()
        sys.exit(1)

    session = build_session(args.header, args.cookie, args.proxy)

    print(f"{C_DIM}  Payload : {C_RESET}{C_RED}{args.payload}{C_RESET}")
    print(f"{C_DIM}  Marker  : {C_RESET}{C_YELLOW}{args.marker}{C_RESET}")
    print(f"{C_DIM}  Method  : {C_RESET}{args.method}")
    print(f"{C_DIM}  Threads : {C_RESET}{args.threads}")
    print(f"{C_DIM}  URLs    : {C_RESET}{len(urls)}")
    if args.proxy:
        print(f"{C_DIM}  Proxy   : {C_RESET}{args.proxy}")

    wordlist_params = load_wordlist(args.wordlist) if args.wordlist else []
    extra_params = [p.strip() for p in args.extra.split(",") if p.strip()] if args.extra else []

    all_hits = []

    for url in urls:
        param_sources = {}

        url_params = extract_params_from_url(url)
        if url_params:
            param_sources["URL query"] = url_params

        if not args.no_html_scan:
            html_params = extract_params_from_html(session, url, args.mode)
            if html_params:
                param_sources["HTML page"] = html_params

        if wordlist_params:
            param_sources["Wordlist"] = wordlist_params

        if extra_params:
            param_sources["Extra/builtin"] = extra_params

        if args.auto:
            merged = []
            seen = set()
            for source, plist in param_sources.items():
                for p in plist:
                    if p not in seen:
                        seen.add(p)
                        merged.append(p)
            selected = merged
            print(f"\n{C_DIM}[auto] Selected {len(selected)} params for {url}{C_RESET}")
        else:
            selected = []
            seen = set()
            for source, plist in param_sources.items():
                chosen = interactive_select(plist, source)
                for p in chosen:
                    if p not in seen:
                        seen.add(p)
                        selected.append(p)

        if not selected:
            print(f"{C_DIM}  No params selected, skipping{C_RESET}")
            continue

        hits = scan_url(session, url, selected, args.payload, args.marker,
                        args.method, args.threads, args.delay)
        all_hits.extend(hits)

    print(f"\n{C_BOLD}{'=' * 60}{C_RESET}")
    if all_hits:
        print(f"{C_RED}{C_BOLD}  REFLECTED: {len(all_hits)} hit(s){C_RESET}\n")
        for h in all_hits:
            print(f"  {C_RED}[+]{C_RESET} {h['param']} -> {h['url'][:120]}")
    else:
        print(f"{C_DIM}  No reflections found.{C_RESET}")

    if args.output and all_hits:
        with open(args.output, "w") as f:
            for h in all_hits:
                f.write(f"{h['param']}\t{h['status']}\t{h['url']}\n")
        print(f"\n{C_GREEN}  Saved to {args.output}{C_RESET}")

    print()


if __name__ == "__main__":
    main()
