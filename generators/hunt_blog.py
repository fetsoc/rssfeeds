from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import List, Optional

import requests
from bs4 import BeautifulSoup
from dateutil import parser as dateparser
from feedgen.feed import FeedGenerator

SITEMAP_URL = "https://hunt.io/sitemap.xml"
BLOG_ROOT = "https://hunt.io/blog"
BLOG_PREFIX = "https://hunt.io/blog/"
OUT_PATH = "docs/feeds/hunt-blog.xml"

# If you want to exclude some /blog/* pages that aren't "posts", add them here:
EXCLUDE_EXACT = {
    "https://hunt.io/blog",
}
EXCLUDE_PREFIXES = (
    # Example: "https://hunt.io/blog/tag/",
)


def fetch(url: str) -> str:
    headers = {
        "User-Agent": "Mozilla/5.0 (rss-feed-generator; +https://github.com/)"
    }
    r = requests.get(url, headers=headers, timeout=45)
    r.raise_for_status()
    return r.text


def parse_sitemap_locs(xml_text: str) -> List[str]:
    root = ET.fromstring(xml_text)

    # Handle XML namespaces (sitemaps almost always have them)
    ns_match = re.match(r"\{(.+)\}", root.tag)
    ns = {"sm": ns_match.group(1)} if ns_match else {}

    locs = []
    for loc in root.findall(".//sm:url/sm:loc", ns) or root.findall(".//url/loc"):
        if loc.text:
            locs.append(loc.text.strip())
    return locs


def is_blog_post(url: str) -> bool:
    if url in EXCLUDE_EXACT:
        return False
    if not url.startswith(BLOG_PREFIX):
        return False
    for p in EXCLUDE_PREFIXES:
        if url.startswith(p):
            return False
    # Heuristic: posts are typically /blog/<slug> (at least one segment after /blog/)
    # This excludes /blog/ itself.
    return url != BLOG_ROOT and url != BLOG_ROOT + "/"


def extract_title_and_date(post_url: str):
    html = fetch(post_url)
    soup = BeautifulSoup(html, "html.parser")

    # Title: prefer og:title, then <title>, then h1
    title = None
    og = soup.select_one('meta[property="og:title"]')
    if og and og.get("content"):
        title = og["content"].strip()

    if not title and soup.title:
        title = soup.title.get_text(strip=True)

    if not title:
        h1 = soup.find("h1")
        title = h1.get_text(" ", strip=True) if h1 else post_url

    # Date: prefer article:published_time
    published = None
    meta_pub = soup.select_one('meta[property="article:published_time"]')
    if meta_pub and meta_pub.get("content"):
        try:
            published = dateparser.parse(meta_pub["content"]).astimezone(timezone.utc)
        except Exception:
            published = None

    # Fallback: scan text for "Jan 28, 2026"
    if not published:
        text = soup.get_text(" ", strip=True)
        m = re.search(
            r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\b\s+\d{1,2},\s+\d{4}",
            text,
        )
        if m:
            try:
                published = dateparser.parse(m.group(0)).replace(tzinfo=timezone.utc)
            except Exception:
                published = None

    return title, published


def main():
    sitemap_xml = fetch(SITEMAP_URL)
    locs = parse_sitemap_locs(sitemap_xml)

    post_urls = [u for u in locs if is_blog_post(u)]

    # Enrich posts with title + date
    enriched = []
    for u in post_urls:
        try:
            title, published = extract_title_and_date(u)
        except Exception:
            title, published = (u, None)
        enriched.append((u, title, published))

    # Sort newest first where dates exist
    enriched.sort(
        key=lambda x: x[2] or datetime(1970, 1, 1, tzinfo=timezone.utc),
        reverse=True,
    )

    fg = FeedGenerator()
    fg.id(BLOG_ROOT)
    fg.title("Hunt.io Blog")
    fg.link(href=BLOG_ROOT, rel="alternate")
    fg.description("Unofficial RSS feed for hunt.io/blog (generated from sitemap.xml)")
    fg.updated(datetime.now(timezone.utc))

    for (u, title, published) in enriched[:50]:
        fe = fg.add_entry()
        fe.id(u)
        fe.title(title)
        fe.link(href=u)
        if published:
            fe.published(published)
            fe.updated(published)
        else:
            fe.updated(datetime.now(timezone.utc))

    fg.rss_file(OUT_PATH, pretty=True)
    print(f"Wrote {OUT_PATH} with {min(len(enriched), 50)} items from {len(post_urls)} post URLs.")


if __name__ == "__main__":
    main()
