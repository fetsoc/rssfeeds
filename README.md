# rssfeeds

A lightweight **RSS/Atom feed factory** powered by **GitHub Actions** + **GitHub Pages**.

Use this repo to generate and host RSS feeds for sources that:

- don’t provide RSS/Atom (but *do* provide a sitemap),
- provide RSS/Atom but you want to **normalize** and **re-host** them in one place,
- are GitHub repos/folders (commits/releases) where Atom feeds already exist.

The output feeds are published as static XML under `docs/feeds/` and can be consumed by any RSS reader, automation pipeline, SIEM/SOAR tooling, or webhook bridge.

---

## Quick start (GitHub UI)

1. **Create / update** `feeds.yml` in the repo root.
2. Commit changes.
3. Run the workflow: **Actions → Build RSS feeds → Run workflow** (or wait for the schedule).
4. After GitHub Pages is enabled, access feeds at:

```
https://<github-username>.github.io/<repo>/feeds/<feed-id>.xml
```

---

## Repository layout

```
.
├─ docs/
│  ├─ feeds/                 # generated RSS output (*.xml)
│  └─ FEEDS_YML.md           # documentation for feeds.yml (optional)
├─ generators/
│  └─ build.py               # feed builder (reads feeds.yml)
├─ .github/
│  └─ workflows/
│     └─ build-feeds.yml     # GitHub Actions workflow
├─ feeds.yml                 # feed definitions
└─ requirements.txt          # Python dependencies
```

---

## Enable GitHub Pages

1. Repo **Settings → Pages**
2. **Source**: “Deploy from a branch”
3. **Branch**: `main`
4. **Folder**: `/docs`
5. Save

After it publishes, your feeds become public URLs under `/feeds/`.

---

## Configure feeds (`feeds.yml`)

`feeds.yml` is the only file you typically edit.

Example minimal config:

```yaml
site_base: "https://<github-username>.github.io/<repo>"
output_dir: "docs/feeds"

feeds:
  - id: "hunt-blog"
    type: "sitemap_blog"
    title: "Hunt.io Blog"
    home_url: "https://hunt.io/blog"
    sitemap_url: "https://hunt.io/sitemap.xml"
    include_prefix: "https://hunt.io/blog/"
    exclude_exact:
      - "https://hunt.io/blog"
      - "https://hunt.io/blog/"
    max_items: 50
    enrich_candidates: 80

  - id: "slimkql-azure-folder-commits"
    type: "passthrough_feed"
    title: "SlimKQL — Azure folder commits"
    home_url: "https://github.com/SlimKQL/Hunting-Queries-Detection-Rules/tree/main/Azure"
    source_feed_url: "https://github.com/SlimKQL/Hunting-Queries-Detection-Rules/commits/main/Azure.atom"
    max_items: 50
```

> **YAML tip:** Use spaces (not tabs) and keep indentation consistent.

For full schema + examples for each template type, see `docs/FEEDS_YML.md`.

---

## Supported template types

The generator supports multiple “template types” (feed builders). The exact list depends on what’s implemented in `generators/build.py`, but typically includes:

- `sitemap_blog` — Build a blog feed from a site’s sitemap (best for JS-rendered blog indexes)
- `sitemap_blog_tag` — Same as above but only include posts matching tag tokens
- `passthrough_feed` — Re-host/normalize an existing RSS/Atom feed
- `html_list` — Scrape a server-rendered list page using a CSS selector
- `json_api` — Build a feed from a JSON endpoint using JMESPath expressions
- `github_releases` — Build a feed from GitHub Releases API

---

## GitHub Sources (easy wins)

GitHub exposes Atom feeds for common repo activity. You can use these with `passthrough_feed`.

Examples:

- **Repo releases**: `https://github.com/<owner>/<repo>/releases.atom`
- **Repo commits (branch)**: `https://github.com/<owner>/<repo>/commits/<branch>.atom`
- **Folder/file commits**: `https://github.com/<owner>/<repo>/commits/<branch>/<path>.atom`

---

## GitHub Actions workflow

The workflow:

- installs dependencies,
- runs `python generators/build.py`,
- commits updated `docs/feeds/*.xml` back to the repo.

If you want to change schedule frequency, edit the cron expression in:

`.github/workflows/build-feeds.yml`

---

## Troubleshooting

### Workflow fails with YAML parse errors
- Most common cause is indentation or tabs in `feeds.yml`.

### A feed returns 0 items
- Ensure your URL/prefix is correct.
- For `sitemap_blog_tag`, confirm the `tag_tokens` actually appear in the post HTML.



---

## Published Feeds

| Feed | Source | RSS URL |
|------|--------|---------|
| Hunt.io Blog | [hunt.io/blog](https://hunt.io/blog) | [hunt-blog.xml](https://fetsoc.github.io/rssfeeds/feeds/hunt-blog.xml) |
| Nozomi Networks Blog — Labs Research | [nozominetworks.com/blog](https://www.nozominetworks.com/blog?tag=labs-research) | [nozomi-labs-research.xml](https://fetsoc.github.io/rssfeeds/feeds/nozomi-labs-research.xml) |
| SlimKQL Hunting Queries — Main folder commits | [GitHub](https://github.com/SlimKQL/Hunting-Queries-Detection-Rules/tree/main) | [slimkql-main-folder-commits.xml](https://fetsoc.github.io/rssfeeds/feeds/slimkql-main-folder-commits.xml) |
| SlimKQL Hunting Queries — Detections AI KQL folder commits | [GitHub](https://github.com/SlimKQL/Detections.AI/tree/main/KQL) | [slimkql-detectionsai-kql-commits.xml](https://fetsoc.github.io/rssfeeds/feeds/slimkql-detectionsai-kql-commits.xml) |
| Darktrace Blog | [darktrace.com/blog](https://www.darktrace.com/blog) | [darktrace-blog.xml](https://fetsoc.github.io/rssfeeds/feeds/darktrace-blog.xml) |
| SonicWall Blog | [sonicwall.com/blog](https://www.sonicwall.com/blog) | [sonicwall-blog.xml](https://fetsoc.github.io/rssfeeds/feeds/sonicwall-blog.xml) |
| CYFIRMA Blog | [cyfirma.com/blogs](https://www.cyfirma.com/blogs/) | [cyfirma-blog.xml](https://fetsoc.github.io/rssfeeds/feeds/cyfirma-blog.xml) |
| Koi Security Blog | [koi.security/blog](https://www.koi.security/blog) | [koi-blog.xml](https://fetsoc.github.io/rssfeeds/feeds/koi-blog.xml) |
| Lookout Blog | [lookout.com/blog](https://www.lookout.com/blog) | [lookout-blog.xml](https://fetsoc.github.io/rssfeeds/feeds/lookout-blog.xml) |
| Cyjax Blog | [cyjax.com/resources (Blog)](https://www.cyjax.com/resources?0402ca75_category_equal=Blog) | [cyjax-blog.xml](https://fetsoc.github.io/rssfeeds/feeds/cyjax-blog.xml) |
| CyberArmor Blog | [cyberarmor.tech/blog](https://cyberarmor.tech/blog) | [cyberarmor-blog.xml](https://fetsoc.github.io/rssfeeds/feeds/cyberarmor-blog.xml) |
| Netcraft Blog | [netcraft.com/resources/blog](https://www.netcraft.com/resources/blog) | [netcraft-blog.xml](https://fetsoc.github.io/rssfeeds/feeds/netcraft-blog.xml) |
| Malwation Blog | [malwation.com/blog](https://www.malwation.com/blog) | [malwation-blog.xml](https://fetsoc.github.io/rssfeeds/feeds/malwation-blog.xml) |
| Cymulate Blog | [cymulate.com/blog](https://cymulate.com/blog/) | [cymulate-blog.xml](https://fetsoc.github.io/rssfeeds/feeds/cymulate-blog.xml) |
| Todyl Threat Research | [todyl.com/threat-research](https://www.todyl.com/threat-research) | [todyl-threat-research.xml](https://fetsoc.github.io/rssfeeds/feeds/todyl-threat-research.xml) |
| ThreatMon Blog | [threatmon.io/blog](https://threatmon.io/blog/) | [threatmon-blog.xml](https://fetsoc.github.io/rssfeeds/feeds/threatmon-blog.xml) |
| Team Cymru Blog | [team-cymru.com/blog](https://www.team-cymru.com/blog) | [team-cymru-blog.xml](https://fetsoc.github.io/rssfeeds/feeds/team-cymru-blog.xml) |
| IBM X-Force Blog | [ibm.com/think/x-force](https://www.ibm.com/think/x-force) | [ibm-xforce-blog.xml](https://fetsoc.github.io/rssfeeds/feeds/ibm-xforce-blog.xml) |
| Expel Blog | [expel.com/blog](https://expel.com/blog/) | [expel-blog.xml](https://fetsoc.github.io/rssfeeds/feeds/expel-blog.xml) |
| Analyst1 Blog | [analyst1.com/category/blog](https://analyst1.com/category/blog/) | [analyst1-blog.xml](https://fetsoc.github.io/rssfeeds/feeds/analyst1-blog.xml) |
| Censys Blog | [censys.com/resources/blog](https://censys.com/resources/blog) | [censys-blog.xml](https://fetsoc.github.io/rssfeeds/feeds/censys-blog.xml) |
| Trellix Blog | [trellix.com/blogs](https://www.trellix.com/blogs/) | [trellix-blog.xml](https://fetsoc.github.io/rssfeeds/feeds/trellix-blog.xml) |
| Push Security Blog | [pushsecurity.com/blog](https://pushsecurity.com/blog/) | [push-security-blog.xml](https://fetsoc.github.io/rssfeeds/feeds/push-security-blog.xml) |
| Splunk Security Blog | [splunk.com/en_us/blog/security](https://www.splunk.com/en_us/blog/security.html) | [splunk-security-blog.xml](https://fetsoc.github.io/rssfeeds/feeds/splunk-security-blog.xml) |
| Guardio Labs | [guard.io/labs](https://guard.io/labs) | [guardio-labs.xml](https://fetsoc.github.io/rssfeeds/feeds/guardio-labs.xml) |
| Semperis Blog | [semperis.com/blog](https://www.semperis.com/blog/) | [semperis-blog.xml](https://fetsoc.github.io/rssfeeds/feeds/semperis-blog.xml) |
| Intel 471 Blog | [intel471.com/blog](https://www.intel471.com/blog) | [intel471-blog.xml](https://fetsoc.github.io/rssfeeds/feeds/intel471-blog.xml) |
| CyberProof Blog | [cyberproof.com/blog](https://www.cyberproof.com/blog/) | [cyberproof-blog.xml](https://fetsoc.github.io/rssfeeds/feeds/cyberproof-blog.xml) |
| Hatching Blog | [hatching.io/blog](https://hatching.io/blog/) | [hatching-blog.xml](https://fetsoc.github.io/rssfeeds/feeds/hatching-blog.xml) |
| eSentire TRU Intelligence Blog | [esentire.com/resources/tru-intelligence-center](https://www.esentire.com/resources/tru-intelligence-center) | [esentire-tru.xml](https://fetsoc.github.io/rssfeeds/feeds/esentire-tru.xml) |
| Malpedia — Inventory Updates | [malpedia.caad.fkie.fraunhofer.de](https://malpedia.caad.fkie.fraunhofer.de/) | [malpedia-inventory-updates.xml](https://fetsoc.github.io/rssfeeds/feeds/malpedia-inventory-updates.xml) |
| Malpedia — New Malware Families | [malpedia.caad.fkie.fraunhofer.de](https://malpedia.caad.fkie.fraunhofer.de/) | [malpedia-families.xml](https://fetsoc.github.io/rssfeeds/feeds/malpedia-families.xml) |
| FalconFeeds Blog | [falconfeeds.io/blogs](https://falconfeeds.io/blogs) | [falconfeeds-blog.xml](https://fetsoc.github.io/rssfeeds/feeds/falconfeeds-blog.xml) |
| AttackerKB — Recent Assessments | [attackerkb.com](https://attackerkb.com/) | [attackerkb.xml](https://fetsoc.github.io/rssfeeds/feeds/attackerkb.xml) |
| Objective-See | [objective-see.org/blog](https://objective-see.org/blog) | [objective-see.xml](https://fetsoc.github.io/rssfeeds/feeds/objective-see.xml) |
| UpGuard News | [upguard.com/news](https://www.upguard.com/news) | [upguard-news.xml](https://fetsoc.github.io/rssfeeds/feeds/upguard-news.xml) |
| ANY.RUN Cybersecurity Blog | [any.run/cybersecurity-blog](https://any.run/cybersecurity-blog/) | [anyrun-blog.xml](https://fetsoc.github.io/rssfeeds/feeds/anyrun-blog.xml) |
| TrustedSec Blog | [trustedsec.com/blog](https://www.trustedsec.com/blog/) | [trustedsec-blog.xml](https://fetsoc.github.io/rssfeeds/feeds/trustedsec-blog.xml) |
| Coveware Blog | [coveware.com/blog](https://www.coveware.com/blog) | [coveware-blog.xml](https://fetsoc.github.io/rssfeeds/feeds/coveware-blog.xml) |
| AhnLab Security Emergency Response Center (EN) | [asec.ahnlab.com/en](https://asec.ahnlab.com/en/) | [ahnlab-en.xml](https://fetsoc.github.io/rssfeeds/feeds/ahnlab-en.xml) |
| Sygnia Blog | [sygnia.co/blog](https://sygnia.co/blog/) | [sygnia-blog.xml](https://fetsoc.github.io/rssfeeds/feeds/sygnia-blog.xml) |
| g0njxa (Medium) | [g0njxa.medium.com](https://g0njxa.medium.com/) | [g0njxa-medium.xml](https://fetsoc.github.io/rssfeeds/feeds/g0njxa-medium.xml) |
| Bridewell Blog | [bridewell.com/insights/blogs](https://www.bridewell.com/insights/blogs/) | [bridewell-blog.xml](https://fetsoc.github.io/rssfeeds/feeds/bridewell-blog.xml) |
| Obsidian Security Blog | [obsidiansecurity.com/blog](https://www.obsidiansecurity.com/blog/) | [obsidian-security-blog.xml](https://fetsoc.github.io/rssfeeds/feeds/obsidian-security-blog.xml) |

---

## Contributing

PRs are welcome.

- Add new template types in `generators/build.py`.
- Document them in `docs/FEEDS_YML.md`.
- Keep configs reproducible and avoid disabling TLS verification globally.

---


