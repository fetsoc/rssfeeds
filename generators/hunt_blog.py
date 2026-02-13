import re
from datetime import datetime, timezone
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from dateutil import parser as dateparser
from feedgen.feed import FeedGenerator

BLOG_URL = "https://hunt.io/blog"
OUT_PATH = "docs/feeds/hunt-blog.xml"


def extract_posts(html):
    soup = BeautifulSoup(html, "html.parser")
    posts = []
    seen = set()

    for a in soup.select('a[href^="/blog/"], a[href*="hunt.io/blog/"]'):
        href = a.get("href")
        if not href:
            continue

        url = urljoin(BLOG_URL, href)
        if url in seen or url.rstrip("/") == BLOG_URL.rstrip("/"):
            continue

        title = a.get_text(" ", strip=True)
        if not title or len(title) < 6:
            continue

        date_found = None
        container = a
        for _ in range(4):
            container = container.parent
            if not container:
                break
            text = container.get_text(" ", strip=True)
            m = re.search(r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \\d{1,2}, \\d{4}", text)
            if m:
                date_found = dateparser.parse(m.group(0)).replace(tzinfo=timezone.utc)
                break

        posts.append({
            "url": url,
            "title": title,
            "date": date_found
        })
        seen.add(url)

    posts.sort(key=lambda p: p["date"] or datetime(1970, 1, 1, tzinfo=timezone.utc), reverse=True)
    return posts


def main():
    html = requests.get(BLOG_URL, timeout=30).text
    posts = extract_posts(html)

    fg = FeedGenerator()
    fg.title("Hunt.io Blog")
    fg.link(href=BLOG_URL)
    fg.description("Unofficial RSS feed for hunt.io/blog")
    fg.updated(datetime.now(timezone.utc))

    for post in posts[:50]:
        fe = fg.add_entry()
        fe.id(post["url"])
        fe.title(post["title"])
        fe.link(href=post["url"])
        if post["date"]:
            fe.published(post["date"])
            fe.updated(post["date"])

    fg.rss_file(OUT_PATH, pretty=True)


if __name__ == "__main__":
    main()
