#!/usr/bin/env python3
"""
otx_sync.py
-----------
Create new AlienVault OTX pulses for selected indicator reports and save the
successful request payload locally as JSON.

The script uses OTX_API_KEY for authentication, never updates an existing pulse,
and never modifies the source Markdown files. A JSON file already present in the
output directory is treated as completed and is skipped on later runs.
Change BATCH for each export, for example: "h2-2026".
"""

from __future__ import annotations

import glob
import json
import os
import re
import sys
import time
from pathlib import Path

from OTXv2 import OTXv2

# Change this one value for the batch to export.
BATCH = "h2-2026"

INDICATORS_DIR = Path("indicators")
OTX_BASE_URL = "https://otx.alienvault.com/pulse"
GITHUB_PAGES_BASE = "https://threatresearch-team.github.io/indicators"

BASE_TAGS = [
    "Meta",
    "ThreatResearch",
    "CIB",
    "social media manipulation",
    "influence operations",
    "disinformation",
    "elections",
]

TYPE_MAP = {
    "url": "URL",
    "domain": "domain",
    "hostname": "hostname",
    "ipv4": "IPv4",
    "ip": "IPv4",
    "ipv6": "IPv6",
    "sha256": "FileHash-SHA256",
    "sha-256": "FileHash-SHA256",
    "md5": "FileHash-MD5",
    "sha1": "FileHash-SHA1",
    "sha-1": "FileHash-SHA1",
    "email": "email",
    "cve": "CVE",
    "social media account": "URL",
    "proxy ip": "IPv4",
    "proxy ipv4": "IPv4",
    "proxy ipv6": "IPv6",
}

ORIGIN_KEYWORDS = {
    "russia": "Russia",
    "china": "China",
    "iran": "Iran",
    "pakistan": "Pakistan",
    "belarus": "Belarus",
    "india": "India",
    "moldova": "Moldova",
    "poland": "Poland",
}

TARGETED_COUNTRY_MAP = {
    "taiwan": "Taiwan",
    "azerbaijan": "Azerbaijan",
    "moldova": "Moldova, Republic of",
    "poland": "Poland",
    "india": "India",
    "pakistan": "Pakistan",
    "iraq": "Iraq",
    "united states": "United States of America",
    "france": "France",
    "israel": "Israel",
    "united kingdom": "United Kingdom",
    "angola": "Angola",
    "ghana": "Ghana",
    "kenya": "Kenya",
    "south africa": "South Africa",
    "mali": "Mali",
    "nigeria": "Nigeria",
    "senegal": "Senegal",
    "cameroon": "Cameroon",
    "gabon": "Gabon",
    "benin": "Benin",
    "burkina faso": "Burkina Faso",
}


def parse_front_matter(content: str) -> dict[str, str]:
    result: dict[str, str] = {}
    match = re.match(r"^---\s*\n(.*?)\n---\s*\n", content, re.DOTALL)
    if not match:
        return result
    for line in match.group(1).splitlines():
        key_value = re.match(r'^([\w_]+):\s*"?(.*?)"?\s*$', line)
        if key_value:
            result[key_value.group(1)] = key_value.group(2)
    return result


def extract_summary(content: str) -> str:
    pattern = (
        r"##\s+Meta[\u2019']s\s+Adversarial\s+Threat\s+Report\s+Network\s+Summary"
        r"\s*\n(.*?)(?=\n##\s+Indicators\s+of\s+Compromise|\Z)"
    )
    match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
    if not match:
        return ""

    summary = match.group(1)
    summary = re.sub(r"<img[^>]*>", "", summary)
    summary = re.sub(r"!\[.*?\]\(.*?\)", "", summary)
    summary = re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", summary)
    summary = re.sub(r"^#{2,}\s+", "", summary, flags=re.MULTILINE)
    summary = re.sub(r"\n{3,}", "\n\n", summary).strip()

    if len(summary) > 1024:
        summary = summary[:1021].rsplit(" ", 1)[0] + "..."
    return summary


def parse_iocs(content: str) -> list[dict[str, str]]:
    indicators: list[dict[str, str]] = []
    parts = re.split(r"##\s+Indicators of Compromise", content, flags=re.IGNORECASE)
    if len(parts) < 2:
        return indicators

    table_block = re.split(r"\n##\s+", parts[1])[0]
    for row in re.findall(r"^\|(.*?)\|$", table_block, re.MULTILINE):
        columns = [column.strip() for column in row.split("|")]
        if len(columns) < 2:
            continue
        raw_type = columns[0].strip("*_ ")
        raw_value = columns[1].strip("*_ ")
        if re.match(r"^[-:]+$", raw_value) or raw_type.lower() in {"indicator type", "type"}:
            continue
        raw_value = raw_value.replace("`", "").replace("[.]", ".")
        otx_type = TYPE_MAP.get(raw_type.lower())
        if otx_type and raw_value:
            indicators.append({"indicator": raw_value, "type": otx_type})
    return indicators


def extract_targeted_countries(title: str, body: str = "") -> list[str]:
    countries: list[str] = []
    match = re.search(r"[Tt]argeting\s+(.+)$", title)
    if match:
        for part in match.group(1).strip().rstrip(".").split(","):
            part = part.strip().lower()
            for keyword, otx_name in TARGETED_COUNTRY_MAP.items():
                if keyword in part and otx_name not in countries:
                    countries.append(otx_name)

    regional_terms = ["sub-saharan africa", "ssa", "eastern europe", "africa"]
    if not countries or any(term in title.lower() for term in regional_terms):
        body_lower = body.lower()
        for keyword, otx_name in TARGETED_COUNTRY_MAP.items():
            if keyword in body_lower and otx_name not in countries:
                countries.append(otx_name)
    return countries


def build_tags(filename: Path, title: str, body: str = "") -> list[str]:
    stem = filename.stem.lower()
    extra: list[str] = []
    for keyword, label in ORIGIN_KEYWORDS.items():
        if keyword in stem and label not in extra:
            extra.append(label)
    for country in extract_targeted_countries(title, body=body):
        if country not in extra:
            extra.append(country)
    return BASE_TAGS + extra


def build_reference_url(filename: Path) -> str:
    return f"{GITHUB_PAGES_BASE}/{filename.stem}/"


def with_retry(callable_, retries: int = 3, delay: int = 10):
    """Retry transient OTX calls, with the same simple backoff as the old script."""
    for attempt in range(1, retries + 1):
        try:
            return callable_()
        except Exception as exc:
            if attempt == retries:
                raise
            print(f"  OTX attempt {attempt} failed: {exc}; retrying in {delay}s")
            time.sleep(delay)
            delay *= 2


def export_report(filepath: Path, otx: OTXv2) -> bool:
    content = filepath.read_text(encoding="utf-8")
    front_matter = parse_front_matter(content)
    stored_url = front_matter.get("otx_pulse_url", "").strip()
    if re.search(r"/pulse/[0-9a-fA-F]{24}/?$", stored_url):
        print(f"Skipping {filepath}: Markdown already contains an OTX pulse URL")
        return False
    title = front_matter.get("title", filepath.stem)
    summary = extract_summary(content)
    indicators = parse_iocs(content)

    if not indicators:
        print(f"Skipping {filepath}: no supported IOCs found")
        return False

    payload = {
        "name": title,
        "public": True,
        "description": summary,
        "indicators": indicators,
        "tags": build_tags(filepath, title, body=summary),
        "tlp": "white",
        "references": [build_reference_url(filepath)],
        "targeted_countries": extract_targeted_countries(title, body=summary),
    }

    print(f"Creating OTX pulse for {filepath}...")
    response = with_retry(lambda: otx.create_pulse(
        name=payload["name"],
        public=payload["public"],
        description=payload["description"],
        indicators=payload["indicators"],
        tags=payload["tags"],
        tlp=payload["tlp"],
        references=payload["references"],
        targeted_countries=payload["targeted_countries"],
    ))
    pulse_id = response.get("id") if isinstance(response, dict) else None
    if not pulse_id:
        raise RuntimeError(f"OTX create response did not contain a pulse id: {response!r}")

    print(f"Created {OTX_BASE_URL}/{pulse_id}")
    return True


def main() -> None:
    api_key = os.environ.get("OTX_API_KEY")
    if not api_key:
        raise SystemExit("OTX_API_KEY is not set")
    otx = OTXv2(api_key)

    batch = BATCH.strip().lower()
    if not batch:
        raise SystemExit("BATCH must not be empty")

    all_files = sorted(Path(path) for path in glob.glob(str(INDICATORS_DIR / "*.md")))
    selected_files = [path for path in all_files if batch in path.name.lower()]

    print(f"Batch: {BATCH}")
    print(f"Found {len(all_files)} indicator file(s); selected {len(selected_files)}")
    if not selected_files:
        raise SystemExit(f"No indicator filenames contain {BATCH!r}")

    exported = 0
    for filepath in selected_files:
        print(f"\nProcessing: {filepath}")
        if export_report(filepath, otx):
            exported += 1

    print(f"\nCreated {exported} OTX pulse(s) in OTX.")
    print("No local files were created or changed, and no existing OTX pulses were updated.")


if __name__ == "__main__":
    main()
