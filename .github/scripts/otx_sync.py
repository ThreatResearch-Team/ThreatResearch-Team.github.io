#!/usr/bin/env python3
"""
otx_sync.py
-----------
Reads all .md files in the indicators/ directory and creates or updates
AlienVault OTX pulses for each file that contains IOCs.

Behaviour:
- Run on-demand only (triggered manually via GitHub Actions workflow_dispatch).
- Extracts the full network summary as the pulse description.
- Sets the reference to the GitHub Pages HTML URL for the indicator page.
- Applies standard tags plus country-of-origin and targeted-country tags
  derived from the filename.
- If a pulse with the same name already exists in the account, it updates it
  instead of creating a duplicate.
"""

import os
import re
import sys
import glob

from OTXv2 import OTXv2

# ---------------------------------------------------------------------------
# OTX indicator type mapping
# ---------------------------------------------------------------------------
TYPE_MAP = {
    'url':                'URL',
    'domain':             'domain',
    'hostname':           'hostname',
    'ipv4':               'IPv4',
    'ip':                 'IPv4',
    'ipv6':               'IPv6',
    'sha256':             'FileHash-SHA256',
    'sha-256':            'FileHash-SHA256',
    'md5':                'FileHash-MD5',
    'sha1':               'FileHash-SHA1',
    'sha-1':              'FileHash-SHA1',
    'email':              'email',
    'cve':                'CVE',
    'social media account': 'URL',   # treat as URL
}

# Base URL for the GitHub Pages site
GITHUB_PAGES_BASE = "https://threatresearch-team.github.io/indicators"

# Standard tags applied to every pulse
BASE_TAGS = [
    'Meta',
    'ThreatResearch',
    'CIB',
    'social media manipulation',
    'influence operations',
    'disinformation',
    'elections',
]

# Country name normalisation: keywords found in filenames → display names
COUNTRY_KEYWORDS = {
    'russia':     'Russia',
    'china':      'China',
    'iran':       'Iran',
    'pakistan':   'Pakistan',
    'belarus':    'Belarus',
    'india':      'India',
    'moldova':    'Moldova',
    'poland':     'Poland',
}

# Targeted-country hints derived from filename keywords
TARGET_KEYWORDS = {
    'ssa':            'Sub-Saharan Africa',
    'africa':         'Sub-Saharan Africa',
    'taiwan':         'Taiwan',
    'azerbaijan':     'Azerbaijan',
    'moldova':        'Moldova',
    'poland':         'Poland',
    'india':          'India',
    'pakistan':       'Pakistan',
    'eastern-europe': 'Eastern Europe',
    'iraq':           'Iraq',
    'us':             'United States',
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_front_matter(content):
    """Return dict of key:value pairs from YAML front matter."""
    fm = {}
    match = re.match(r'^---\s*\n(.*?)\n---\s*\n', content, re.DOTALL)
    if match:
        for line in match.group(1).splitlines():
            kv = re.match(r'^(\w+):\s*"?(.*?)"?\s*$', line)
            if kv:
                fm[kv.group(1)] = kv.group(2)
    return fm


def extract_summary(content):
    """
    Extract the body text from the '## Meta's Adversarial Threat Report Network Summary'
    section (or the first substantial paragraph after the H1 title).
    Strips Markdown image tags and link syntax, returning plain text.
    """
    # Try the dedicated summary section first
    section_match = re.search(
        r"##\s+Meta'?s? Adversarial Threat Report Network Summary\s*\n(.*?)(?=\n##\s+|\Z)",
        content, re.DOTALL | re.IGNORECASE
    )
    if section_match:
        raw = section_match.group(1)
    else:
        # Fall back to the first paragraph after the H1
        h1_match = re.search(r'^#\s+.+\n+(.*?)(?=\n##\s+|\Z)', content, re.DOTALL | re.MULTILINE)
        raw = h1_match.group(1) if h1_match else ''

    # Strip HTML image tags
    raw = re.sub(r'<img[^>]*>', '', raw)
    # Strip Markdown image syntax
    raw = re.sub(r'!\[.*?\]\(.*?\)', '', raw)
    # Convert Markdown links to plain text
    raw = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', raw)
    # Collapse whitespace
    raw = re.sub(r'\n{3,}', '\n\n', raw).strip()
    return raw


def parse_iocs(content):
    """Return list of {'indicator': ..., 'type': ...} dicts from the IOC table."""
    iocs = []
    parts = re.split(r'##\s+Indicators of Compromise', content, flags=re.IGNORECASE)
    if len(parts) < 2:
        return iocs

    table_block = re.split(r'\n##\s+', parts[1])[0]

    for row in re.findall(r'^\|(.*?)\|$', table_block, re.MULTILINE):
        cols = [c.strip() for c in row.split('|')]
        if len(cols) < 2:
            continue

        raw_type  = cols[0].strip('*_ ')
        raw_value = cols[1].strip('*_ ')

        # Skip header and separator rows
        if re.match(r'^[-:]+$', raw_value) or raw_type.lower() in ('indicator type', 'type'):
            continue

        # Clean code fences and defanging
        raw_value = raw_value.replace('`', '').replace('[.]', '.')

        otx_type = TYPE_MAP.get(raw_type.lower())
        if otx_type and raw_value:
            iocs.append({'indicator': raw_value, 'type': otx_type})

    return iocs


def build_tags_from_filename(filename):
    """
    Derive origin and target country tags from the filename.
    e.g. 'meta-h1-2026-russia-based-cib-network-1.md'
    → ['Russia', 'Sub-Saharan Africa'] (added to BASE_TAGS)
    """
    stem = os.path.splitext(os.path.basename(filename))[0].lower()
    extra = []

    for kw, label in COUNTRY_KEYWORDS.items():
        if kw in stem:
            extra.append(label)

    for kw, label in TARGET_KEYWORDS.items():
        if kw in stem and label not in extra:
            extra.append(label)

    return extra


def build_reference_url(filename):
    """Return the GitHub Pages HTML URL for the indicator page."""
    stem = os.path.splitext(os.path.basename(filename))[0]
    return f"{GITHUB_PAGES_BASE}/{stem}/"


def find_existing_pulse(otx, pulse_name):
    """
    Search the authenticated user's pulses for one matching pulse_name.
    Returns the pulse ID string, or None if not found.
    """
    try:
        page = 1
        while True:
            results = otx.get_my_pulses(page=page)
            if not results:
                break
            for pulse in results:
                if pulse.get('name', '').strip() == pulse_name.strip():
                    return pulse['id']
            page += 1
    except Exception as e:
        print(f"  Warning: could not search existing pulses: {e}")
    return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def sync_to_otx(api_key, md_files):
    otx = OTXv2(api_key)

    for filepath in sorted(md_files):
        print(f"\n{'='*60}")
        print(f"Processing: {filepath}")

        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        fm          = parse_front_matter(content)
        title       = fm.get('title', os.path.splitext(os.path.basename(filepath))[0])
        summary     = extract_summary(content)
        iocs        = parse_iocs(content)
        ref_url     = build_reference_url(filepath)
        extra_tags  = build_tags_from_filename(filepath)
        all_tags    = BASE_TAGS + [t for t in extra_tags if t not in BASE_TAGS]

        print(f"  Title:     {title}")
        print(f"  IOCs:      {len(iocs)}")
        print(f"  Reference: {ref_url}")
        print(f"  Tags:      {all_tags}")

        if not iocs:
            print("  No IOCs found — skipping.")
            continue

        # Check for an existing pulse with the same name
        print("  Checking for existing pulse...")
        existing_id = find_existing_pulse(otx, title)

        try:
            if existing_id:
                print(f"  Found existing pulse: {existing_id} — updating...")
                # Update description, tags, references, and replace all indicators
                otx.edit_pulse(
                    pulse_id=existing_id,
                    body={
                        'description': summary,
                        'tags':        all_tags,
                        'references':  [ref_url],
                    }
                )
                otx.replace_pulse_indicators(
                    pulse_id=existing_id,
                    new_indicators=iocs
                )
                print(f"  Updated successfully.")
            else:
                print("  No existing pulse found — creating new pulse...")
                response = otx.create_pulse(
                    name=title,
                    public=True,
                    description=summary,
                    indicators=iocs,
                    tags=all_tags,
                    tlp='white',
                    references=[ref_url],
                )
                new_id = response.get('id', 'unknown')
                print(f"  Created successfully. Pulse ID: {new_id}")

        except Exception as e:
            print(f"  ERROR: {e}")
            sys.exit(1)

    print(f"\n{'='*60}")
    print("All files processed.")


if __name__ == '__main__':
    api_key = os.environ.get('OTX_API_KEY')
    if not api_key:
        print("ERROR: OTX_API_KEY environment variable is not set.")
        sys.exit(1)

    md_files = glob.glob('indicators/*.md')
    if not md_files:
        print("No .md files found in indicators/ — nothing to do.")
        sys.exit(0)

    print(f"Found {len(md_files)} indicator file(s).")
    sync_to_otx(api_key, md_files)
