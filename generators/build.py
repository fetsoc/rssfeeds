from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import feedparser
import jmespath
import requests
import yaml
from bs4 import BeautifulSoup
from dateutil import parser as dateparser
from feedgen.feed import FeedGenerator


# ----------------------------
# Common helpers
# ----------------------------
def fetch_text(url: str) -> str:
    headers = {
        "User-Agent": "Mozilla/5.0 (rssfeeds generator; +https://github.com/fetsoc/rssfeeds)"
    }
    r = requests.get(url, headers=headers, timeout=45)
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

    # Enrich first N and then sort by published date
    enriched: List[Dict[str, Any]] = []
    for u in urls[:enrich_candidates]:
        try:
            title, published, desc = enrich_from_post_page(u)
        except Exception:
            title, published, desc = (u, None, None)
        enriched.append(
            {"url": u, "title": title, "published": published, "description": desc}
        )

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

    items: List[Dict[str, Any]] = []
    for u in urls[:max_items]:
        try:
            title, published, desc = enrich_from_post_page(u)
        except Exception:
            title, published, desc = (u, None, None)
        items.append({"url": u, "title": title, "published": published, "description": desc})

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

def build_malpedia_inventory_updates(feed: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Build RSS items from the 'Inventory Updates' section on the Malpedia homepage.

    Strategy:
      - Fetch homepage HTML
      - Find the 'Inventory Updates' block
      - Parse each update row: date/time + numeric counters
      - Emit items describing what changed
    """
    url = feed.get("page_url", "https://malpedia.caad.fkie.fraunhofer.de/")
    max_items = int(feed.get("max_items", 50))

    html = fetch_text(url)
    soup = BeautifulSoup(html, "html.parser")

    # Find the header containing 'Inventory Updates'
    header = None
    for tag in soup.find_all(["h1", "h2", "h3", "h4", "strong", "b", "div", "span"]):
        if tag.get_text(" ", strip=True).lower() == "inventory updates":
            header = tag
            break

    if not header:
        # Fallback: search for partial match
        for tag in soup.find_all(["h1", "h2", "h3", "h4", "strong", "b", "div", "span"]):
            if "inventory updates" in tag.get_text(" ", strip=True).lower():
                header = tag
                break

    if not header:
        # Nothing found; return empty but don't crash
        return []

    # Attempt to locate the container after the header
    container = header.find_parent()
    # Walk forward looking for a table or list that contains the updates
    updates_block = None
    for _ in range(6):
        if not container:
            break
        # Look for a table first
        tbl = container.find("table")
        if tbl:
            updates_block = tbl
            break
        # Otherwise look for a list
        ul = container.find(["ul", "ol"])
        if ul:
            updates_block = ul
            break
        container = container.find_next()

    items: List[Dict[str, Any]] = []

    def parse_numbers(text: str) -> List[int]:
        return [int(x) for x in re.findall(r"\b\\d+\\b", text)]

    def parse_datetime_from_text(text: str) -> Optional[datetime]:
        # Example seen on homepage: "5 Feb 2026 19:13:55"
        # We'll rely on dateutil parsing.
        return safe_parse_date(text)

    # Case A: table
    if updates_block and updates_block.name == "table":
        rows = updates_block.find_all("tr")
        for r in rows:
            row_text = r.get_text(" ", strip=True)
            if not row_text:
                continue
            # crude split: date/time first, then counters
            # extract a date-ish prefix by trying parse on the full string and then trimming
            # easiest: search for something like "Feb 2026" pattern
            m = re.search(r"\\b\\d{1,2}\\s+[A-Za-z]{3,}\\s+\\d{4}\\s+\\d{2}:\\d{2}:\\d{2}\\b", row_text)
            dt = safe_parse_date(m.group(0)) if m else None
            nums = parse_numbers(row_text)
            if not dt and nums:
                # not a valid row
                continue

            title = f"Malpedia Inventory Update — {dt.date().isoformat() if dt else 'Unknown date'}"
            desc = f"Raw update row: {row_text}"

            items.append({
                "url": url,
                "title": title,
                "published": dt,
                "description": desc
            })

    # Case B: list (ul/ol)
    elif updates_block and updates_block.name in ("ul", "ol"):
        for li in updates_block.find_all("li"):
            row_text = li.get_text(" ", strip=True)
            if not row_text:
                continue

            m = re.search(r"\\b\\d{1,2}\\s+[A-Za-z]{3,}\\s+\\d{4}\\s+\\d{2}:\\d{2}:\\d{2}\\b", row_text)
            dt = safe_parse_date(m.group(0)) if m else None

            title = f"Malpedia Inventory Update — {dt.date().isoformat() if dt else 'Unknown date'}"
            desc = f"Raw update line: {row_text}"

            items.append({
                "url": url,
                "title": title,
                "published": dt,
                "description": desc
            })

    # Fallback: if no table/list found, just grab nearby text lines after header
    else:
        # Grab next few lines of text after header area
        block_text = header.find_parent().get_text("\\n", strip=True)
        lines = [ln.strip() for ln in block_text.splitlines() if ln.strip()]
        # Keep only lines that look like date entries
        for ln in lines:
            if re.search(r"\\b\\d{1,2}\\s+[A-Za-z]{3,}\\s+\\d{4}\\b", ln):
                dt = parse_datetime_from_text(ln)
                title = f"Malpedia Inventory Update — {dt.date().isoformat() if dt else 'Unknown date'}"
                items.append({
                    "url": url,
                    "title": title,
                    "published": dt,
                    "description": ln
                })

    # Sort newest first
    items.sort(
        key=lambda x: x["published"] or datetime(1970, 1, 1, tzinfo=timezone.utc),
        reverse=True
    )

    return items[:max_items]

# ----------------------------
# Dispatcher
# ----------------------------
BUILDERS = {
    "sitemap_blog": build_sitemap_blog,
    "passthrough_feed": build_passthrough_feed,
    "html_list": build_html_list,
    "json_api": build_json_api,
    "github_releases": build_github_releases,
    "sitemap_blog_tag": build_sitemap_blog_tag,
    "malpedia_inventory_updates": build_malpedia_inventory_updates,
}


def main():
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

        items = builder(feed)

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


if __name__ == "__main__":
    main()
