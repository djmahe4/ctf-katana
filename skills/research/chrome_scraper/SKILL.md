---
name: chrome-intelligence-scraper
description: Autonomous Chrome-based Intelligence Scraper. Use for vulnerability discovery across CVE lists, GitHub Advisories, and Nuclei Templates.
risk: low
source: local
---

# Chrome Intelligence Scraper

This skill provides the "Eyes and Ears" of the Purple Engine, ensuring a continuous stream of high-fidelity threat intelligence and vulnerability data.

## Core Triggers

- `Intel_Discovery`: General monitoring of `NVD`, `GitHub Advisories`, or `HackerOne` reports.
- `CVE_Detail_Extraction`: Fetching deep technical metadata for a specific `CVE_ID`.
- `Template_Scouting`: Monitoring `Nuclei` or `Metasploit` repos for new, weaponized PoCs.
- `Vendor_Security_Advisory`: Parsing official security pages for a `Software_Product_Name`.
- `Search_Query`: Executing a custom `Intel_Query` across prioritized security domains.

## Mandatory Context

- `Target_Sources`: (`cve`, `nuclei`, `github`, `nvd`, `all`).
- `Query_Keywords`: Keywords to search for (e.g., "RCE on NGINX").
- `Lookback_Period`: (Optional) Timeframe for detection (e.g., "last 24 hours").
- `Output_Schema`: Formatting for the enriched intelligence brief.

## Orchestration Workflow

1. **Scheduling**: Based on user triggers or discovery needs, identify target URLs.
2. **Scraping**: Use the `chrome_scraper/run.py` script (which integrates with `scraper.py`) for data acquisition.
3. **Semantic Analysis**: Parse the raw findings to identify impact scores, product names, and exploit availability.
4. **Deduplication**: Compare findings across multiple intelligence feeds.
5. **Enrichment**: Cross-reference with the `vulnerability_catalog` to flag "Gold" (new/unpatched) or "Forgotten" (old/unpatched) vulnerabilities.

## When to Use

- When needing the latest vulnerability data to generate a new CTF challenge.
- When performing threat intelligence gathering for a specific software product.
- To maintain the project's internal security knowledge base.

## When NOT to Use

- For generic web crawling (use a standard search tool instead).
- When target sources have strict anti-scraping measures (unless a proxy is configured).

## Strategy: Hyper-Efficient Intelligence

> [!TIP]
> Go beyond simple scraping; infer relationships and cross-reference data points. Your output should be a concise, enriched intelligence brief, highlighting key takeaways and potential defensive implications.
