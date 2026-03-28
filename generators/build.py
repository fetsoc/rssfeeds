from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import cloudscraper
import feedparser
import jmespath
import requests
import yaml
from bs4 import BeautifulSoup
from dateutil import parser as dateparser
from feedgen.feed import FeedGenerator
import json


# ----------------------------
# Enrichment cache
# ----------------------------
_CACHE_FILE = os.path.join(os.path.dirname(__file__), "..", "generators", "enrich_cache.json")
_enrich_cache: Dict[str, Dict[str, Any]] = {}


def _load_cache() -> None:
    global _enrich_cache
    try:
        with open(_CACHE_FILE, "r", encoding="utf-8") as f:
            _enrich_cache = json.load(f)
    except FileNotFoundError:
        _enrich_cache = {}
    except Exception as e:
        print(f"Warning: could not load enrich cache: {e}")
        _enrich_cache = {}


def _save_cache() -> None:
    try:
        with open(_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(_enrich_cache, f)
    except Exception as e:
        print(f"Warning: could not save enrich cache: {e}")


ENRICH_WORKERS = 8  # concurrent page-fetch threads


# ----------------------------
# Common helpers
# ----------------------------
def fetch_text(url: str) -> str:
    scraper = cloudscraper.create_scraper()
    r = scraper.get(url, timeout=45)
    r.raise_for_status()

    # Fix mojibake (â€™ etc.) when encoding is missing/wrong
    r.encoding = r.apparent_encoding or "utf-8"
    return r.text


def fetch_json(url: str, headers: Optional[Dict[str, str]] = None) -> Any:
    base_headers = {
        "User-Agent": "Mozilla/5.0 (rssfeeds generator; +https://github.com/fetsoc/rssfeeds)",
        "Accept": "application/json",
    }
    if headers:
        base_headers.update(headers)

    r = requests.get(url, headers=base_headers, timeout=45)
    r.raise_for_status()
    return r.json()


def safe_parse_date(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = dateparser.parse(str(value))
        if not dt.tzinfo:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def rss_datetime(dt: datetime) -> datetime:
    # feedgen expects datetime; ensure UTC tzinfo present
    return dt.astimezone(timezone.utc)


# ----------------------------
# Feed writers
# ----------------------------
def write_feed(
    out_file: str,
    site_base: str,
    feed_id: str,
    title: str,
    home_url: str,
    description: str,
    items: List[Dict[str, Any]],
) -> None:
    fg = FeedGenerator()
    fg.id(home_url)
    fg.title(title)
    fg.link(href=home_url, rel="alternate")
    fg.description(description)
    fg.updated(datetime.now(timezone.utc))

    # Add rel=self (helps some readers)
    self_url = f"{site_base.rstrip('/')}/feeds/{feed_id}.xml"
    fg.link(href=self_url, rel="self")

    # Items should already be sorted newest-first
    for it in items:
        fe = fg.add_entry()
        fe.id(it["url"])
        fe.title(it["title"])
        fe.link(href=it["url"])

        if it.get("description"):
            fe.description(it["description"])

        if it.get("published"):
            fe.published(rss_datetime(it["published"]))
            fe.updated(rss_datetime(it["published"]))
        else:
            fe.updated(datetime.now(timezone.utc))

    fg.rss_file(out_file, pretty=True)


# ----------------------------
# TEMPLATE TYPE 1: sitemap_blog
# ----------------------------
def parse_sitemap_locs(xml_text: str) -> List[str]:
    root = ET.fromstring(xml_text)
    ns_match = re.match(r"\{(.+)\}", root.tag)
    ns = {"sm": ns_match.group(1)} if ns_match else {}

    locs = []
    for loc in root.findall(".//sm:url/sm:loc", ns) or root.findall(".//url/loc"):
        if loc.text:
            locs.append(loc.text.strip())
    return locs


def enrich_from_post_page(url: str) -> Tuple[str, Optional[datetime], Optional[str]]:
    """Fetch and parse a post page, using/updating the in-memory cache."""
    if url in _enrich_cache:
        cached = _enrich_cache[url]
        published = safe_parse_date(cached.get("published")) if cached.get("published") else None
        return cached.get("title", url), published, cached.get("desc")

    html = fetch_text(url)
    soup = BeautifulSoup(html, "html.parser")

    # title preference: og:title -> h1 -> <title>
    title = None
    og_title = soup.select_one('meta[property="og:title"]')
    if og_title and og_title.get("content"):
        title = og_title["content"].strip()
    if not title:
        h1 = soup.find("h1")
        if h1:
            title = h1.get_text(" ", strip=True)
    if not title and soup.title:
        title = soup.title.get_text(strip=True)
    if not title:
        title = url

    # description preference: og:description
    desc = None
    og_desc = soup.select_one('meta[property="og:description"]')
    if og_desc and og_desc.get("content"):
        desc = og_desc["content"].strip()

    # date preference: article:published_time then visible "Mon DD, YYYY"
    published = None
    meta_pub = soup.select_one('meta[property="article:published_time"]')
    if meta_pub and meta_pub.get("content"):
        published = safe_parse_date(meta_pub["content"])

    if not published:
        text = soup.get_text(" ", strip=True)
        m = re.search(
            r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\b\s+\d{1,2},\s+\d{4}",
            text,
        )
        if m:
            published = safe_parse_date(m.group(0))

    # Store in cache (published as ISO string)
    _enrich_cache[url] = {
        "title": title,
        "published": published.isoformat() if published else None,
        "desc": desc,
    }

    return title, published, desc


def build_sitemap_blog(feed: Dict[str, Any]) -> List[Dict[str, Any]]:
    sitemap_url = feed["sitemap_url"]
    include_prefix = feed["include_prefix"]
    exclude_exact = set(feed.get("exclude_exact", []))
    max_items = int(feed.get("max_items", 50))
    enrich_candidates = int(feed.get("enrich_candidates", 80))

    xml_text = fetch_text(sitemap_url)
    locs = parse_sitemap_locs(xml_text)

    urls = []
    for u in locs:
        if u in exclude_exact:
            continue
        if u.startswith(include_prefix):
            # must have something after prefix
            if u != include_prefix.rstrip("/"):
                urls.append(u)

    # Enrich first N in parallel, then sort by published date
    candidates = urls[:enrich_candidates]
    results: Dict[str, Tuple[str, Optional[datetime], Optional[str]]] = {}

    with ThreadPoolExecutor(max_workers=ENRICH_WORKERS) as pool:
        future_to_url = {pool.submit(enrich_from_post_page, u): u for u in candidates}
        for future in as_completed(future_to_url):
            u = future_to_url[future]
            try:
                results[u] = future.result()
            except Exception:
                results[u] = (u, None, None)

    enriched: List[Dict[str, Any]] = [
        {"url": u, "title": results[u][0], "published": results[u][1], "description": results[u][2]}
        for u in candidates
    ]

    enriched.sort(
        key=lambda x: x["published"] or datetime(1970, 1, 1, tzinfo=timezone.utc),
        reverse=True,
    )

    return enriched[:max_items]


# ----------------------------
# TEMPLATE TYPE 2: passthrough_feed
# ----------------------------
def build_passthrough_feed(feed: Dict[str, Any]) -> List[Dict[str, Any]]:
    source_url = feed["source_feed_url"]
    max_items = int(feed.get("max_items", 50))

    parsed = feedparser.parse(source_url)

    items: List[Dict[str, Any]] = []
    for e in parsed.entries[:max_items]:
        url = getattr(e, "link", None) or getattr(e, "id", None)
        title = getattr(e, "title", None) or url or "Untitled"

        published = None
        # feedparser can provide published_parsed
        if getattr(e, "published", None):
            published = safe_parse_date(e.published)
        elif getattr(e, "updated", None):
            published = safe_parse_date(e.updated)

        desc = getattr(e, "summary", None)

        if url:
            items.append({"url": url, "title": title, "published": published, "description": desc})

    # sort if dates exist
    items.sort(
        key=lambda x: x["published"] or datetime(1970, 1, 1, tzinfo=timezone.utc),
        reverse=True,
    )
    return items[:max_items]


# ----------------------------
# TEMPLATE TYPE 3: html_list
# ----------------------------
def build_html_list(feed: Dict[str, Any]) -> List[Dict[str, Any]]:
    list_url = feed["list_url"]
    item_link_selector = feed["item_link_selector"]
    max_items = int(feed.get("max_items", 30))

    html = fetch_text(list_url)
    soup = BeautifulSoup(html, "html.parser")

    seen = set()
    urls: List[str] = []
    for a in soup.select(item_link_selector):
        href = a.get("href")
        if not href:
            continue
        url = urljoin(list_url, href)
        if url in seen:
            continue
        seen.add(url)
        urls.append(url)

    candidates = urls[:max_items]
    results: Dict[str, Tuple[str, Optional[datetime], Optional[str]]] = {}

    with ThreadPoolExecutor(max_workers=ENRICH_WORKERS) as pool:
        future_to_url = {pool.submit(enrich_from_post_page, u): u for u in candidates}
        for future in as_completed(future_to_url):
            u = future_to_url[future]
            try:
                results[u] = future.result()
            except Exception:
                results[u] = (u, None, None)

    items: List[Dict[str, Any]] = [
        {"url": u, "title": results[u][0], "published": results[u][1], "description": results[u][2]}
        for u in candidates
    ]

    items.sort(
        key=lambda x: x["published"] or datetime(1970, 1, 1, tzinfo=timezone.utc),
        reverse=True,
    )
    return items[:max_items]


# ----------------------------
# TEMPLATE TYPE 4: json_api
# ----------------------------
def build_json_api(feed: Dict[str, Any]) -> List[Dict[str, Any]]:
    api_url = feed["api_url"]
    items_expr = feed["items_expr"]
    title_expr = feed["title_expr"]
    url_expr = feed["url_expr"]
    date_expr = feed.get("date_expr")
    max_items = int(feed.get("max_items", 50))

    data = fetch_json(api_url)
    items = jmespath.search(items_expr, data) or []
    out: List[Dict[str, Any]] = []

    for obj in items[: max_items * 2]:
        title = jmespath.search(title_expr, obj) or "Untitled"
        url = jmespath.search(url_expr, obj)
        if not url:
            continue
        published = safe_parse_date(jmespath.search(date_expr, obj)) if date_expr else None
        out.append({"url": url, "title": str(title), "published": published, "description": None})

    out.sort(
        key=lambda x: x["published"] or datetime(1970, 1, 1, tzinfo=timezone.utc),
        reverse=True,
    )
    return out[:max_items]


# ----------------------------
# TEMPLATE TYPE 5: github_releases
# ----------------------------
def build_github_releases(feed: Dict[str, Any]) -> List[Dict[str, Any]]:
    owner = feed["owner"]
    repo = feed["repo"]
    max_items = int(feed.get("max_items", 30))

    api_url = f"https://api.github.com/repos/{owner}/{repo}/releases"
    headers = {}

    # Optional: use token if present to avoid rate limits
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    releases = fetch_json(api_url, headers=headers)
    out: List[Dict[str, Any]] = []

    for r in releases[:max_items]:
        url = r.get("html_url")
        title = r.get("name") or r.get("tag_name") or url
        published = safe_parse_date(r.get("published_at"))
        desc = r.get("body")

        if url:
            out.append({"url": url, "title": title, "published": published, "description": desc})

    out.sort(
        key=lambda x: x["published"] or datetime(1970, 1, 1, tzinfo=timezone.utc),
        reverse=True,
    )
    return out[:max_items]

def build_sitemap_blog_tag(feed: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Build a feed by:
      1) reading sitemap URLs
      2) selecting URLs under include_prefix (e.g., /blog/)
      3) fetching each post page and including it only if it contains one of the tag tokens
         (e.g., 'tag=labs-research' or 'Labs Research')
    """
    sitemap_url = feed["sitemap_url"]
    include_prefix = feed["include_prefix"]
    exclude_exact = set(feed.get("exclude_exact", []))
    max_items = int(feed.get("max_items", 50))

    # These strings are searched in the HTML to determine tag membership.
    # Example: ["tag=labs-research", "Labs Research"]
    tag_tokens = [t.lower() for t in feed.get("tag_tokens", [])]
    match_mode = feed.get("tag_match_mode", "any").lower()  # "any" or "all"

    # Safety caps so Actions doesn't spend forever crawling
    scan_limit = int(feed.get("scan_limit", 250))           # max pages to inspect
    enrich_limit = int(feed.get("enrich_limit", 120))       # max pages to enrich if tag matches

    xml_text = fetch_text(sitemap_url)
    locs = parse_sitemap_locs(xml_text)

    # Candidate post URLs from sitemap
    candidates = []
    for u in locs:
        if u in exclude_exact:
            continue
        if u.startswith(include_prefix) and u != include_prefix.rstrip("/"):
            candidates.append(u)

    items: List[Dict[str, Any]] = []
    checked = 0
    enriched = 0

    for url in candidates:
        if checked >= scan_limit or len(items) >= max_items or enriched >= enrich_limit:
            break
        checked += 1

        try:
            html = fetch_text(url)
            html_lc = html.lower()

            # Determine whether this post belongs to the desired tag set
            if tag_tokens:
                if match_mode == "all":
                    ok = all(tok in html_lc for tok in tag_tokens)
                else:
                    ok = any(tok in html_lc for tok in tag_tokens)
                if not ok:
                    continue

            # If tagged, extract title/date/desc from the same HTML (avoid a 2nd fetch)
            soup = BeautifulSoup(html, "html.parser")

            # title: og:title -> h1 -> <title>
            title = None
            og_title = soup.select_one('meta[property="og:title"]')
            if og_title and og_title.get("content"):
                title = og_title["content"].strip()
            if not title:
                h1 = soup.find("h1")
                if h1:
                    title = h1.get_text(" ", strip=True)
            if not title and soup.title:
                title = soup.title.get_text(strip=True)
            if not title:
                title = url

            # desc: og:description
            desc = None
            og_desc = soup.select_one('meta[property="og:description"]')
            if og_desc and og_desc.get("content"):
                desc = og_desc["content"].strip()

            # date: article:published_time -> fallback visible "Mon DD, YYYY"
            published = None
            meta_pub = soup.select_one('meta[property="article:published_time"]')
            if meta_pub and meta_pub.get("content"):
                published = safe_parse_date(meta_pub["content"])
            if not published:
                text = soup.get_text(" ", strip=True)
                m = re.search(
                    r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\b\s+\d{1,2},\s+\d{4}",
                    text,
                )
                if m:
                    published = safe_parse_date(m.group(0))

            items.append({"url": url, "title": title, "published": published, "description": desc})
            enriched += 1

        except Exception:
            continue

    # Sort newest-first
    items.sort(
        key=lambda x: x["published"] or datetime(1970, 1, 1, tzinfo=timezone.utc),
        reverse=True,
    )

    return items[:max_items]


# ----------------------------
# TEMPLATE TYPE: objective_see
# ----------------------------
def build_objective_see(feed: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Build a feed for Objective-See blog, correctly handling the 9 legacy
    fragment-URL articles (blog.html#blogEntryN) that exist only as anchors
    in the single-page archive at objective-see.com/blog.html.

    For fragment-URL articles:
      - Fetches objective-see.com/blog.html once (lazy-loaded)
      - Extracts the specific entry's content between anchor tags
      - Writes a static HTML wrapper at static_out_dir/objective-see-{anchor}.html
        so EIQ's RSS transport can fetch a clean single-article page
      - Uses the GitHub Pages URL of that static file as the RSS <link>

    For individual-page articles (no #):
      - Passes the URL through unchanged; EIQ fetches and extracts normally
    """
    from bs4 import NavigableString

    rss_url = feed.get("rss_url", "https://objective-see.org/rss.xml")
    archive_url = feed.get("archive_url", "https://objective-see.com/blog.html")
    static_out_dir = feed.get("static_out_dir", "docs/feeds")
    static_base_url = feed.get("static_base_url", "https://fetsoc.github.io/rssfeeds/feeds")
    max_items = int(feed.get("max_items", 50))

    parsed = feedparser.parse(rss_url)
    archive_soup: Optional[Any] = None  # lazy-loaded for fragment articles

    items: List[Dict[str, Any]] = []

    for entry in parsed.entries:
        url = getattr(entry, "link", "") or getattr(entry, "id", "")
        title = getattr(entry, "title", url)
        rss_desc = getattr(entry, "summary", None)

        published = None
        if getattr(entry, "published", None):
            published = safe_parse_date(entry.published)
        elif getattr(entry, "updated", None):
            published = safe_parse_date(entry.updated)

        if "#" in url:
            # Legacy fragment-URL article: extract content from the archive page.
            fragment = url.split("#", 1)[1]  # e.g. "blogEntry1"

            # Lazy-fetch the archive page (fetched only once for all fragments).
            if archive_soup is None:
                archive_html = fetch_text(archive_url)
                archive_soup = BeautifulSoup(archive_html, "html.parser")

            anchor = archive_soup.find("a", attrs={"name": fragment})
            if not anchor:
                # Anchor missing; fall back to RSS description only, skip static page.
                items.append({"url": url, "title": title, "published": published,
                               "description": rss_desc})
                continue

            # Collect all sibling nodes from this anchor up to the next blogEntry anchor.
            content_nodes: List[str] = []
            node = anchor.next_sibling
            while node is not None:
                if (
                    hasattr(node, "attrs")
                    and isinstance(node.attrs.get("name"), str)
                    and node.attrs["name"].startswith("blogEntry")
                ):
                    break  # Reached the next entry's anchor — stop.
                content_nodes.append(str(node))
                node = node.next_sibling

            # Try to extract publication date from the blogDate div if RSS had none.
            if not published:
                for node_str in content_nodes:
                    date_soup = BeautifulSoup(node_str, "html.parser")
                    date_el = date_soup.find(class_="blogDate")
                    if date_el:
                        published = safe_parse_date(date_el.get_text(strip=True))
                        break

            article_inner_html = "".join(content_nodes).strip()

            # Write a minimal static HTML page that EIQ can fetch.
            # The transport is configured to extract <div class="pageContent">,
            # so we wrap the article content in exactly that element.
            static_filename = f"objective-see-{fragment}.html"
            static_path = os.path.join(static_out_dir, static_filename)
            os.makedirs(static_out_dir, exist_ok=True)
            with open(static_path, "w", encoding="utf-8") as fh:
                fh.write(
                    f'<!DOCTYPE html>\n<html><head>'
                    f'<meta charset="utf-8"><title>{title}</title>'
                    f'</head>\n<body>\n'
                    f'<div class="pageContent">\n{article_inner_html}\n</div>\n'
                    f'</body></html>\n'
                )

            item_url = f"{static_base_url.rstrip('/')}/{static_filename}"
        else:
            # Normal individual-page article — EIQ fetches and extracts as usual.
            item_url = url

        if item_url:
            items.append({
                "url": item_url,
                "title": title,
                "published": published,
                "description": rss_desc,
            })

    items.sort(
        key=lambda x: x["published"] or datetime(1970, 1, 1, tzinfo=timezone.utc),
        reverse=True,
    )
    return items[:max_items]


def build_malpedia_inventory_updates(feed: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Build RSS items from Malpedia's 'Inventory Updates' section.

    Improvements over the original:
    - Handles multiple batches on the homepage (multiple timestamps)
    - Less brittle timestamp detection (looks within the section)
    - Works if widget is table-based OR link/list-based
    - More reliable scoping to avoid grabbing unrelated tables elsewhere
    """
    page_url = feed.get("page_url", "https://malpedia.caad.fkie.fraunhofer.de/")
    max_items = int(feed.get("max_items", 50))
    use_details_fallback = bool(feed.get("use_details_fallback", True))

    html = fetch_text(page_url)
    soup = BeautifulSoup(html, "html.parser")

    def abs_url(href: str) -> str:
        return urljoin(page_url, href)

    # 1) Find a node containing "Inventory Updates"
    header = None
    for tag in soup.find_all(["h1", "h2", "h3", "h4", "strong", "b", "div", "span"]):
        txt = tag.get_text(" ", strip=True).lower()
        if "inventory updates" in txt:
            header = tag
            break
    if not header:
        return []

    # 2) Use a scoped section container (walk up a few parents)
    section_root = header
    for _ in range(4):
        if section_root.parent:
            section_root = section_root.parent

    # 3) Find all batch timestamps inside the section
    # Example seen on homepage: "15 Feb 2026 12:59:49 ..."
    ts_re = re.compile(r"\b\d{1,2}\s+[A-Za-z]{3,}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\b")

    # Collect candidate nodes containing timestamps in document order
    batch_nodes = []
    for node in section_root.find_all(string=True):
        s = str(node).strip()
        if not s:
            continue
        m = ts_re.search(s)
        if m:
            batch_nodes.append((node, m.group(0)))

    items: List[Dict[str, Any]] = []

    def add_item(family: str, msg: str, href: Optional[str], batch_dt: Optional[datetime], batch_stats: Optional[str]) -> None:
        if not family or not msg:
            return

        if href:
            link = abs_url(href)
        elif use_details_fallback:
            link = abs_url(f"/details/{family}")
        else:
            link = page_url

        desc = msg
        if batch_dt:
            desc = f"{desc} (Batch: {batch_dt.strftime('%Y-%m-%d %H:%M:%S %Z')})"
        if batch_stats:
            desc = f"{desc} (Batch stats: {batch_stats})"

        items.append({
            "url": link,
            "title": f"{family} — {msg}",
            "published": batch_dt,
            "description": desc
        })

    # 4) For each timestamp node, find the nearest table following it within the section
    # This supports multiple batches if Malpedia renders multiple timestamp+table blocks.
    used_tables = set()
    for node, ts in batch_nodes:
        batch_dt = safe_parse_date(ts)

        # attempt to get numeric stats from the same text fragment
        txt = str(node).strip()
        tail = txt.split(ts, 1)[-1].strip()
        nums = re.findall(r"\b\d+\b", tail)
        batch_stats = " ".join(nums) if nums else None

        # Find the next table after the timestamp node
        # Step 1: ascend to an element, then find next table
        parent_el = node.parent if hasattr(node, "parent") else None
        next_table = None
        if parent_el:
            next_table = parent_el.find_next("table")

        # Ensure the found table is inside our section_root
        if next_table and section_root not in next_table.parents:
            next_table = None

        if not next_table:
            continue

        # Avoid re-processing the same table if multiple timestamps match inside it
        table_id = id(next_table)
        if table_id in used_tables:
            continue
        used_tables.add(table_id)

        # Parse rows
        for tr in next_table.find_all("tr"):
            if tr.find("th"):
                continue
            tds = tr.find_all("td")
            if len(tds) < 2:
                continue

            left, right = tds[0], tds[1]
            family = left.get_text(" ", strip=True)
            msg = right.get_text(" ", strip=True)

            if not family or not msg:
                continue
            if family.upper() == "SYMBOL" and msg.upper() == "COMMON_NAME":
                continue

            a = left.find("a")
            href = a.get("href") if a else None

            add_item(family, msg, href, batch_dt, batch_stats)

    # 5) Fallback: if no table items were discovered, try link-based parsing within section
    # This handles layouts where the widget is not a table or is partially gated.
    if not items:
        for a in section_root.select('a[href]'):
            href = a.get("href", "")
            if "/details/" not in href:
                continue
            family = a.get_text(" ", strip=True)
            container_text = a.parent.get_text(" ", strip=True) if a.parent else ""
            msg = container_text.replace(family, "").strip(" -—:\t") or "Updated"
            add_item(family, msg, href, None, None)

    # 6) De-dupe and sort
    seen = set()
    uniq = []
    for it in items:
        key = (it["url"], it["title"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(it)

    uniq.sort(
        key=lambda x: x["published"] or datetime(1970, 1, 1, tzinfo=timezone.utc),
        reverse=True
    )
    return uniq[:max_items]

# ----------------------------
# TEMPLATE TYPE 7: malpedia_families
# ----------------------------
def build_malpedia_families(feed: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Build RSS items from Malpedia's public API by tracking new malware families.
    Uses a state file to detect families added since last run.
    """
    api_url = feed.get("api_url", "https://malpedia.caad.fkie.fraunhofer.de/api/list/families")
    max_items = int(feed.get("max_items", 50))
    state_file = feed.get("state_file", "malpedia_families_state.json")
    
    # Fetch current families from API
    try:
        current_families = fetch_json(api_url)
        if not isinstance(current_families, list):
            current_families = []
    except Exception as e:
        print(f"Error fetching Malpedia families: {e}")
        return []
    
    # Load previous state
    previous_families = []
    if os.path.exists(state_file):
        try:
            with open(state_file, 'r', encoding='utf-8') as f:
                previous_families = json.load(f)
        except Exception:
            previous_families = []
    
    # Find new families
    previous_set = set(previous_families)
    new_families = [f for f in current_families if f not in previous_set]
    
    # Save current state
    try:
        with open(state_file, 'w', encoding='utf-8') as f:
            json.dump(current_families, f)
    except Exception as e:
        print(f"Warning: Could not save state file: {e}")
    
    # Create RSS items for new families
    items: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc)
    
    for family in new_families[:max_items]:
        items.append({
            "url": f"https://malpedia.caad.fkie.fraunhofer.de/details/{family}",
            "title": f"New Malware Family: {family}",
            "published": now,
            "description": f'New malware family "{family}" has been added to Malpedia.',
        })
    
    # Sort by family name (since they all have same timestamp)
    items.sort(key=lambda x: x["title"])
    
    print(f"Malpedia: {len(current_families)} total families, {len(new_families)} new")
    
    return items[:max_items]


# ----------------------------
# Dispatcher
# ----------------------------
# TEMPLATE TYPE: falconfeeds_blog
# ----------------------------
def build_falconfeeds_blog(feed: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Build a feed for FalconFeeds blog via their CMS JSON API.
    Endpoint: https://cms.falconfeeds.io/api/blogapi?page=N
    Returns 12 items per page, newest-first. Paginates until max_items reached.
    """
    cms_api_base = feed.get("cms_api_url", "https://cms.falconfeeds.io/api/blogapi")
    blog_base = feed.get("blog_base_url", "https://falconfeeds.io/blogs")
    max_items = int(feed.get("max_items", 50))

    items: List[Dict[str, Any]] = []
    page = 1

    while len(items) < max_items:
        try:
            page_data = fetch_json(f"{cms_api_base}?page={page}")
        except Exception as e:
            print(f"FalconFeeds API page {page} failed: {e}")
            break

        if not isinstance(page_data, list) or not page_data:
            break

        for obj in page_data:
            slug = obj.get("slug")
            if not slug:
                continue
            url = f"{blog_base.rstrip('/')}/{slug}"
            title = obj.get("title") or obj.get("metaTitle") or slug
            desc = obj.get("metaDescription") or obj.get("blogDescription")
            published = safe_parse_date(obj.get("createdAt"))
            items.append({"url": url, "title": title, "published": published, "description": desc})
            if len(items) >= max_items:
                break

        page += 1

    # API returns newest-first, but sort to be safe
    items.sort(
        key=lambda x: x["published"] or datetime(1970, 1, 1, tzinfo=timezone.utc),
        reverse=True,
    )
    return items[:max_items]


# ----------------------------
BUILDERS = {
    "sitemap_blog": build_sitemap_blog,
    "passthrough_feed": build_passthrough_feed,
    "html_list": build_html_list,
    "json_api": build_json_api,
    "github_releases": build_github_releases,
    "sitemap_blog_tag": build_sitemap_blog_tag,
    "objective_see": build_objective_see,
    "malpedia_inventory_updates": build_malpedia_inventory_updates,
    "malpedia_families": build_malpedia_families,
    "falconfeeds_blog": build_falconfeeds_blog,
}


def main():
    _load_cache()

    with open("feeds.yml", "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    site_base = cfg["site_base"].rstrip("/")
    out_dir = cfg.get("output_dir", "docs/feeds")

    ensure_dir(out_dir)

    for feed in cfg.get("feeds", []):
        feed_id = feed["id"]
        feed_type = feed["type"]
        title = feed["title"]
        home_url = feed.get("home_url") or feed.get("list_url") or feed.get("source_feed_url")

        builder = BUILDERS.get(feed_type)
        if not builder:
            raise ValueError(f"Unknown feed type: {feed_type}")

        try:
            items = builder(feed)
        except Exception as e:
            print(f"WARNING: Skipping {feed_id} — {e}", flush=True)
            continue

        out_file = os.path.join(out_dir, f"{feed_id}.xml")
        write_feed(
            out_file=out_file,
            site_base=site_base,
            feed_id=feed_id,
            title=title,
            home_url=home_url,
            description=f"Generated feed ({feed_type})",
            items=items,
        )

        print(f"Built {feed_id}: {len(items)} items -> {out_file}")

    _save_cache()


if __name__ == "__main__":
    main()
