from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import List, Optional, Tuple

import requests
from bs4 import BeautifulSoup
from dateutil import parser as dateparser
from feedgen.feed import FeedGenerator

# ---- Config ----
SITEMAP_URL = "https://hunt.io/sitemap.xml"
BLOG_ROOT = "https://hunt.io/blog"
BLOG_PREFIX = "https://hunt.io/blog/"
OUT_PATH = "docs/feeds/hunt-blog.xml"

# Set this AFTER you enable GitHub Pages, e.g.:
FEED_SELF_URL = "https://fetsoc.github.io/rssfeeds/feeds/hunt-blog.xml"
#FEED_SELF_URL = ""  # leave blank if you don't know it yet

# Exclude specific URLs or URL prefixes if desired
EXCLUDE_EXACT = {
    BLOG_ROOT,
    BLOG_ROOT + "/",
    # "https://hunt.io/blog/sql",  # example: uncomment if you want to exclude it
}
EXCLUDE_PREFIXES = (
    # "https://hunt.io/blog/tag/",  # example: if tag pages ever appear
)

# Tune how many posts to include
MAX_ITEMS = 50

# How many candidate blog URLs to enrich (fetch title/desc/date for).
# Keep this modest so Actions runs fast. We sort after enrichment.
ENRICH_CANDIDATES = 80

# ---- Helpers ----
def fetch(url: str) -> str:
    """
    Fetch a URL with a browser-like User-Agent and robust decoding.
    This helps avoid mojibake (â€™ etc.) when encoding headers are inconsistent.
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (rss-feed-generator; +https://github.com/)"
    }
    r = requests.get(url, headers=headers, timeout=45)
    r.raise_for_status()

    # Force a sane encoding; many CDNs/pages omit or misreport charset headers
    r.encoding = r.apparent_encoding or "utf-8"
    return r.text


def parse_sitemap_locs(xml_text: str) -> List[str]:
    """
    Parse <loc> values from a sitemap <urlset>.
    Handles the standard sitemap namespace.
    """
    root = ET.fromstring(xml_text)

    ns_match = re.match(r"\{(.+)\}", root.tag)
    ns = {"sm": ns_match.group(1)} if ns_match else {}

    locs = []
    # Namespaced form (typical)
    for loc in root.findall(".//sm:url/sm:loc", ns):
        if loc.text:
            locs.append(loc.text.strip())

    # Non-namespaced fallback
    if not locs:
        for loc in root.findall(".//url/loc"):
            if loc.text:
                locs.append(loc.text.strip())

    return locs


def is_blog_post(url: str) -> bool:
    """
    True if URL looks like a real blog post under /blog/<slug>
    """
    if url in EXCLUDE_EXACT:
        return False
    if not url.startswith(BLOG_PREFIX):
        return False
    for p in EXCLUDE_PREFIXES:
        if url.startswith(p):
            return False

    # Must have at least one segment after /blog/
    # e.g. https://hunt.io/blog/some-post  -> OK
    #      https://hunt.io/blog           -> not OK (excluded above)
    return url != BLOG_ROOT and url != BLOG_ROOT + "/"


def extract_title_date_desc(post_url: str) -> Tuple[str, Optional[datetime], Optional[str]]:
    """
    Fetches the post page and extracts:
    - Title (og:title -> h1 -> <title>)
    - Published date (article:published_time -> "Mon DD, YYYY" pattern)
    - Description (og:description)
    """
    html = fetch(post_url)
    soup = BeautifulSoup(html, "html.parser")

    # Title
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
        title = post_url

    # Description
    desc = None
    og_desc = soup.select_one('meta[property="og:description"]')
    if og_desc and og_desc.get("content"):
        desc = og_desc["content"].strip()

    # Published date
    published = None
    meta_pub = soup.select_one('meta[property="article:published_time"]')
    if meta_pub and meta_pub.get("content"):
        try:
            published = dateparser.parse(meta_pub["content"]).astimezone(timezone.utc)
        except Exception:
            published = None

    # Fallback: look for "Jan 28, 2026"
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

    return title, published, desc


def main():
    sitemap_xml = fetch(SITEMAP_URL)
    locs = parse_sitemap_locs(sitemap_xml)

