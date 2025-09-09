#!/usr/bin/env python3
import argparse
import csv
import gzip
import json
import re
import sys
import time
import warnings
from collections import OrderedDict, defaultdict, deque
from io import BytesIO
from typing import List, Tuple, Dict
from urllib.parse import urljoin, urlparse, urlunparse

import requests
import certifi
from urllib3.exceptions import InsecureRequestWarning
from bs4 import BeautifulSoup

warnings.filterwarnings('ignore', message='Unverified HTTPS request')
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

UA = {"User-Agent": "Mozilla/5.0 (+universal-keyword-extractor)"}
VERBOSE = False

def logv(msg: str):
    if VERBOSE:
        print(msg)

def safe_bs(data: str, parser_type: str = "xml") -> BeautifulSoup:
    try:
        return BeautifulSoup(data, parser_type)
    except Exception:
        if parser_type == "xml":
            logv("XML parser not available, falling back to html.parser")
            return BeautifulSoup(data, 'html.parser')
        return BeautifulSoup(data, 'html.parser')

def sanitize_input_url(raw: str) -> str:
    s = (raw or "").strip()
    if (s.startswith("[") and s.endswith("]")) or (s.startswith("<") and s.endswith(">")) or (s.startswith("(") and s.endswith(")")):
        s = s[1:-1].strip()
    return s

def normalize_base(url: str) -> str:
    url = sanitize_input_url(url)
    if not url.startswith("http"):
        url = "https://" + url
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}/"

def to_http(url: str) -> str:
    try:
        return url.replace("https://", "http://", 1) if url.startswith("https://") else url
    except:
        return url

def set_response_encoding(resp: requests.Response):
    try:
        if not resp.encoding and resp.apparent_encoding:
            resp.encoding = resp.apparent_encoding
    except Exception:
        pass

def build_session(timeout: int, retries: int = 2, backoff: float = 0.6, insecure: bool = False) -> requests.Session:
    s = requests.Session()
    s.headers.update(UA)
    s.request_timeout = timeout
    s.request_retries = retries
    s.request_backoff = backoff
    s.verify = False if insecure else certifi.where()
    return s

def http_get_text(session: requests.Session, url: str) -> str | None:
    tries = getattr(session, "request_retries", 1) + 1
    timeout = getattr(session, "request_timeout", 25)
    
    for attempt in range(tries):
        try:
            logv(f"GET (text) {url}")
            r = session.get(url, timeout=timeout, allow_redirects=True, verify=session.verify)
            logv(f" -> status {r.status_code}")
            if r.status_code == 200:
                set_response_encoding(r)
                logv(f" -> text bytes {len(r.text.encode('utf-8','ignore'))}")
                return r.text
            elif 300 <= r.status_code < 500 and r.status_code != 429:
                return None
        except Exception as e:
            logv(f"GET (text) {url} error: {type(e).__name__}")
            if "SSL" in str(e) or "CERTIFICATE" in str(e):
                alt = to_http(url)
                if alt != url:
                    logv(f"Retry over HTTP: {alt}")
                    try:
                        r2 = session.get(alt, timeout=timeout, allow_redirects=True, verify=False)
                        logv(f" -> HTTP retry status {r2.status_code}")
                        if r2.status_code == 200:
                            set_response_encoding(r2)
                            return r2.text
                    except Exception as e2:
                        logv(f"HTTP retry failed: {type(e2).__name__}")
        
        if attempt < tries - 1:
            time.sleep(getattr(session, "request_backoff", 0.6))
    
    return None

def http_get_bytes(session: requests.Session, url: str) -> bytes | None:
    tries = getattr(session, "request_retries", 1) + 1
    timeout = getattr(session, "request_timeout", 25)
    
    for attempt in range(tries):
        try:
            logv(f"GET (bytes) {url}")
            r = session.get(url, timeout=timeout, allow_redirects=True, stream=True, verify=session.verify)
            logv(f" -> status {r.status_code}")
            if r.status_code == 200:
                content = r.content
                logv(f" -> content bytes {len(content)}")
                return content
            elif 300 <= r.status_code < 500 and r.status_code != 429:
                return None
        except Exception as e:
            logv(f"GET (bytes) {url} error: {type(e).__name__}")
            if "SSL" in str(e) or "CERTIFICATE" in str(e):
                alt = to_http(url)
                if alt != url:
                    logv(f"Retry over HTTP: {alt}")
                    try:
                        r2 = session.get(alt, timeout=timeout, allow_redirects=True, stream=True, verify=False)
                        logv(f" -> HTTP retry status {r2.status_code}")
                        if r2.status_code == 200:
                            content = r2.content
                            return content
                    except Exception as e2:
                        logv(f"HTTP retry failed: {type(e2).__name__}")
        
        if attempt < tries - 1:
            time.sleep(getattr(session, "request_backoff", 0.6))
    
    return None

def normalize_canonical(base_url: str, current_url: str, canonical_href: str | None) -> str:
    use_url = current_url
    if canonical_href:
        try:
            use_url = urljoin(current_url, canonical_href.strip())
        except Exception:
            use_url = current_url
    
    parsed = urlparse(use_url)
    parsed = parsed._replace(fragment="")
    host = parsed.hostname or ""
    port = parsed.port
    scheme = parsed.scheme or urlparse(base_url).scheme or "https"
    
    if port and ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = host
    else:
        netloc = parsed.netloc or host
    
    norm = parsed._replace(scheme=scheme, netloc=netloc)
    return urlunparse(norm)

EXTRA_SITEMAP_PATHS = [
    "wp-sitemap.xml",
    "sitemap_index.xml", 
    "sitemap.xml",
    "sitemap_index.xml.gz",
    "sitemap.xml.gz",
    "sitemap/index.xml",
    "sitemap1.xml",
    "sitemap-1.xml",
    "sitemap-news.xml",
    "sitemap-posts.xml", 
    "sitemap-pages.xml",
    "?sitemap=1",
    "?jetpack-sitemap=1"
]

def try_decompress_gzip_if_needed(content: bytes, url: str) -> str | None:
    if not content:
        return None
    
    looks_gz = url.lower().endswith(".gz")
    if not looks_gz and len(content) >= 2:
        looks_gz = content[0] == 0x1F and content[1] == 0x8B
    
    if looks_gz:
        try:
            with gzip.GzipFile(fileobj=BytesIO(content)) as gz:
                data = gz.read()
            text = data.decode("utf-8", "replace")
            logv(f"Decompressed gzip from {url} -> {len(text)} chars")
            return text
        except Exception as e:
            logv(f"Gzip decompress failed for {url}: {e}")
            return None
    
    try:
        return content.decode("utf-8", "replace")
    except Exception as e:
        logv(f"Decode failed for {url}: {e}")
        return None

def fetch_robots_sitemaps(session: requests.Session, base_url: str) -> list[str]:
    robots_url = urljoin(base_url, "robots.txt")
    logv(f"Fetching robots: {robots_url}")
    txt = http_get_text(session, robots_url)
    sitemaps: list[str] = []
    
    if txt:
        logv("robots.txt loaded")
        for raw in txt.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            
            parts = line.split(":", 1)
            if len(parts) == 2:
                key, val = parts[0].strip().lower(), parts[1].strip()
                if key == "sitemap" and val:
                    if val.startswith(("http://", "https://")):
                        sitemaps.append(val)
                        logv(f"robots Sitemap: {val}")
                    else:
                        absu = urljoin(base_url, val)
                        sitemaps.append(absu)
                        logv(f"robots Sitemap (rel): {val} -> {absu}")
    else:
        logv("robots.txt not available or empty")

    if sitemaps:
        logv("Robots provided sitemaps; skipping fallback probes.")
    else:
        logv("No robots sitemaps found, trying fallbacks...")
        for fb in EXTRA_SITEMAP_PATHS:
            test = urljoin(base_url, fb)
            logv(f"Probe sitemap candidate: {test}")
            b = http_get_bytes(session, test)
            if not b:
                continue
            
            text = try_decompress_gzip_if_needed(b, test)
            if text and ("<urlset" in text or "<sitemapindex" in text or "<loc>" in text):
                sitemaps.append(test)
                logv(f" -> XML sitemap detected at: {test}")
                break

    seen = set()
    out = []
    for s in sitemaps:
        if s not in seen:
            seen.add(s)
            out.append(s)
    
    return out

def parse_xml_locs(xml_text: str) -> list[str]:
    soup = safe_bs(xml_text, "xml")
    locs = [loc.text.strip() for loc in soup.find_all("loc") if loc and loc.text and loc.text.strip()]
    return locs

def is_sitemapindex(xml_text: str) -> bool:
    soup = safe_bs(xml_text, "xml")
    tag = soup.find(lambda t: getattr(t, "name", None) and t.name.lower().endswith("sitemapindex"))
    return tag is not None

def expand_sitemaps(session: requests.Session, sitemap_urls: list[str], max_children: int = 5000) -> list[str]:
    urls: list[str] = []
    child_sitemaps: list[str] = []

    for sm in sitemap_urls:
        logv(f"Fetch sitemap: {sm}")
        b = http_get_bytes(session, sm)
        if not b:
            continue
        
        xml = try_decompress_gzip_if_needed(b, sm)
        if not xml:
            continue
        
        if is_sitemapindex(xml):
            children = parse_xml_locs(xml)
            child_sitemaps.extend(children)
            logv(f"Sitemap index: {sm} -> {len(children)} child sitemaps")
        else:
            here = parse_xml_locs(xml)
            urls.extend(here)
            logv(f"URL set: {sm} -> {len(here)} URLs")

    for sm in child_sitemaps[:max_children]:
        logv(f"Child sitemap: {sm}")
        b = http_get_bytes(session, sm)
        if not b:
            continue
        
        xml = try_decompress_gzip_if_needed(b, sm)
        if not xml:
            continue
        
        here = parse_xml_locs(xml)
        urls.extend(here)
        logv(f" -> {len(here)} URLs")

    uniq_sorted = sorted(set(u for u in urls if u))
    logv(f"Total URLs from sitemaps: {len(uniq_sorted)}")
    return uniq_sorted

EXCLUDE_KEYWORDS = {
    'written by', 'time to read', 'read more', 'continue reading', 
    'share this', 'related posts', 'recent posts', 'categories',
    'tags', 'leave a comment', 'post navigation', 'search for',
    'copyright', 'all rights reserved', 'privacy policy', 'terms of service',
    'home', 'about', 'contact', 'blog', 'news', 'page', 'post', 'article',
    'menu', 'navigation', 'header', 'footer', 'sidebar', 'content',
    'main', 'section', 'div', 'span', 'link', 'image', 'video'
}

def extract_jsonld_keywords_only(html: str) -> list[str]:
    soup = safe_bs(html, "html.parser")
    all_keywords = set()
    
    scripts = soup.find_all("script", attrs={"type": re.compile(r"^application/ld\+json$", re.I)})
    
    for script in scripts:
        raw_json = script.string or script.text or ""
        if not raw_json.strip():
            continue
        
        try:
            parsed_data = json.loads(raw_json)
        except json.JSONDecodeError:
            try:
                cleaned = re.sub(r',\s*(\]|\})', r'\1', raw_json)
                parsed_data = json.loads(cleaned)
            except json.JSONDecodeError:
                continue
        
        if not parsed_data:
            continue
        
        items_to_process = []
        if isinstance(parsed_data, dict):
            if '@graph' in parsed_data:
                items_to_process = parsed_data['@graph']
            else:
                items_to_process = [parsed_data]
        elif isinstance(parsed_data, list):
            items_to_process = parsed_data
        
        for item in items_to_process:
            if not isinstance(item, dict):
                continue
            
            keyword_value = item.get('keywords')
            if not keyword_value or not isinstance(keyword_value, str):
                continue
            
            normalized = keyword_value.replace('.', ',')
            parts = [kw.strip() for kw in normalized.split(',') if kw.strip()]
            
            for kw in parts:
                kw_clean = kw.strip()
                kw_lower = kw_clean.lower()
                
                if (kw_clean and 
                    2 <= len(kw_lower) <= 50 and 
                    not kw_lower.isdigit() and
                    kw_lower not in EXCLUDE_KEYWORDS):
                    all_keywords.add(kw_clean)
    
    return sorted(list(all_keywords))

def extract_keywords_from_html(html: str, base_url: str, current_url: str) -> tuple[str, list[str]]:
    soup = safe_bs(html, "html.parser")
    canonical_href = None
    for ln in soup.find_all("link", rel=True, href=True):
        rel = ln.get("rel")
        if isinstance(rel, list):
            rel = " ".join(rel)
        rel = (rel or "").lower()
        if "canonical" in rel:
            canonical_href = ln.get("href")
            break
    
    canonical_url = normalize_canonical(base_url, current_url, canonical_href)
    keywords = extract_jsonld_keywords_only(html)
    
    return canonical_url, keywords

def write_keyword_csv(filename: str, keyword_to_urls: Dict[str, List[str]]):
    with open(filename, "w", encoding="utf-8") as f:
        for keyword, urls in sorted(keyword_to_urls.items(), key=lambda x: x[0].lower()):
            if urls:
                primary_url = urls[0]
                f.write(f"{keyword};{primary_url}\n")

def write_kw_csv(filename: str, keyword_to_urls: Dict[str, List[str]]):
    with open(filename, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Keyword", "URLs"])
        for kw, urls in sorted(keyword_to_urls.items(), key=lambda x: x[0].lower()):
            w.writerow([kw, ", ".join(sorted(set(urls)))])

def write_cannibalization(filename: str, keyword_to_urls: Dict[str, List[str]]) -> int:
    affected = [kw for kw, urls in keyword_to_urls.items() if len(set(urls)) >= 2]
    if not affected:
        return 0
    
    with open(filename, "w", encoding="utf-8") as f:
        for kw in sorted(affected, key=str.lower):
            unique_urls = sorted(set(keyword_to_urls[kw]))
            f.write(f"{kw}, {', '.join(unique_urls)}\n")
    
    return len(affected)

def read_urls_from_csv(csv_path: str) -> list[str]:
    urls: list[str] = []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.reader(f, delimiter=";")
        for row in reader:
            if not row:
                continue
            url = row[-1].strip()
            if url:
                urls.append(url)
    
    seen = set()
    out = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    
    return out

class KeywordAggregator:
    def __init__(self):
        self.keyword_to_urls = defaultdict(list)
    
    def add_keywords(self, canonical_url: str, keywords: list[str]):
        for kw in keywords:
            normalized = kw.strip().lower()
            if normalized and normalized not in EXCLUDE_KEYWORDS and 2 <= len(normalized) <= 50:
                self.keyword_to_urls[kw.strip()].append(canonical_url)
    
    def get_results(self):
        result = {}
        for kw, urls in self.keyword_to_urls.items():
            unique_urls = list(dict.fromkeys(urls))
            result[kw] = unique_urls
        return result

def process_urls(session: requests.Session, base_url: str, urls: list[str], sleep_ms: int) -> tuple[OrderedDict, dict]:
    url_to_keywords: OrderedDict[str, list[str]] = OrderedDict()
    aggregator = KeywordAggregator()

    print(f"Base URL: {base_url}")
    print(f"Discovered URL count: {len(urls)}")

    for u in urls:
        html = http_get_text(session, u)
        if not html:
            print(f"No keywords -> {u}")
            continue
        
        canonical_url, keywords = extract_keywords_from_html(html, base_url, u)
        if keywords:
            print(f"Keywords: {len(keywords)} -> {canonical_url}")
        else:
            print(f"No keywords -> {canonical_url}")

        if canonical_url not in url_to_keywords:
            url_to_keywords[canonical_url] = keywords
        else:
            existing = url_to_keywords[canonical_url]
            seen = set(k.lower() for k in existing)
            for k in keywords:
                if k.lower() not in seen:
                    existing.append(k)
                    seen.add(k.lower())
            url_to_keywords[canonical_url] = existing

        aggregator.add_keywords(canonical_url, keywords)

        if sleep_ms > 0:
            time.sleep(sleep_ms / 1000.0)

    return url_to_keywords, aggregator.get_results()

def discover_urls(session: requests.Session, site_input: str, max_children: int, sleep_ms: int) -> tuple[str, list[str], list[str]]:
    base_url = normalize_base(site_input)
    sitemaps = fetch_robots_sitemaps(session, base_url)
    
    print(f"Base URL: {base_url}")
    print("Sitemaps:")
    for sm in sitemaps:
        print(f" - {sm}")
    
    urls = expand_sitemaps(session, sitemaps, max_children=max_children) if sitemaps else []
    print(f"Total URLs discovered via sitemaps: {len(urls)}")

    return base_url, sitemaps, urls

def main():
    global VERBOSE

    parser = argparse.ArgumentParser(description="Discover sitemaps, extract page-level keywords, and detect cannibalization.")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--site", help="Domain or URL, e.g., example.com or https://example.com/")
    src.add_argument("--csv", help="CSV file with seed URLs (semicolon-separated; rightmost column is URL).")
    parser.add_argument("--timeout", type=int, default=25, help="HTTP timeout seconds per request (default 25).")
    parser.add_argument("--sleep-ms", type=int, default=100, help="Sleep between fetches in milliseconds (politeness).")
    parser.add_argument("--retries", type=int, default=2, help="HTTP retries for transient errors (default 2).")
    parser.add_argument("--backoff", type=float, default=0.6, help="Backoff between retries in seconds (default 0.6).")
    parser.add_argument("--max-children", type=int, default=5000, help="Max child sitemaps to expand from indexes.")
    parser.add_argument("--max-urls", type=int, default=0, help="Optional cap on number of URLs to process (0 = no cap).")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging of discovery and fetching.")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL verification completely (recommended for dev).")

    args = parser.parse_args()
    VERBOSE = args.verbose

    session = build_session(
        timeout=args.timeout, 
        retries=args.retries, 
        backoff=args.backoff,
        insecure=args.insecure
    )

    if args.insecure:
        logv("SSL verification disabled (--insecure mode)")
    else:
        logv(f"SSL verification enabled with certifi bundle: {session.verify}")

    if args.csv:
        urls = read_urls_from_csv(args.csv)
        if args.max_urls and len(urls) > args.max_urls:
            urls = urls[:args.max_urls]
        if urls:
            base_url = normalize_base(urls[0])
        else:
            print("No URLs found in CSV.")
            return
        
        print(f"Base URL: {base_url}")
        print("Discovered URL count (from CSV):", len(urls))
        url_to_keywords, keyword_to_urls = process_urls(session, base_url, urls, sleep_ms=args.sleep_ms)
    else:
        base_url, sitemaps, urls = discover_urls(
            session,
            args.site,
            max_children=args.max_children,
            sleep_ms=args.sleep_ms,
        )
        if args.max_urls and len(urls) > args.max_urls:
            urls = urls[:args.max_urls]
        
        url_to_keywords, keyword_to_urls = process_urls(session, base_url, urls, sleep_ms=args.sleep_ms)

    write_keyword_csv("keyword.csv", keyword_to_urls)
    write_kw_csv("kw.csv", keyword_to_urls)
    affected = write_cannibalization("cannibalization.txt", keyword_to_urls)

    print("\nGenerated files:")
    print(" - keyword.csv (Keyword -> Primary Landing Page, semicolon-separated, no header)")
    print(" - kw.csv (Keyword -> All URLs)")
    if affected > 0:
        print(f"WARNING: Cannibalization detected for {affected} keywords; see cannibalization.txt")
    else:
        print("No cannibalization detected (no keyword maps to 2+ URLs).")

if __name__ == "__main__":
    main()
