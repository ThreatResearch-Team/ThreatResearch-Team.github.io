#!/usr/bin/env python3
"""
otx_sync.py
-----------
Reads all .md files in the indicators/ directory and creates or updates
AlienVault OTX pulses for each file that contains IOCs.

Fixes vs previous version:
- Handles the Unicode right-single-quote (U+2019) in section header
- Extracts full summary including ### sub-sections
- Populates targeted_countries from the title/description line
- Reference points to GitHub Pages HTML URL
- Idempotent: updates existing pulse instead of creating duplicates
"""

import os
import re
import sys
import glob

from OTXv2 import OTXv2

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GITHUB_PAGES_BASE = "https://threatresearch-team.github.io/indicators"

BASE_TAGS = [
    'Meta',
    'ThreatResearch',
    'CIB',
    'social media manipulation',
    'influence operations',
    'disinformation',
    'elections',
]

# OTX indicator type mapping
TYPE_MAP = {
    'url':                  'URL',
    'domain':               'domain',
    'hostname':             'hostname',
    'ipv4':                 'IPv4',
    'ip':                   'IPv4',
    'ipv6':                 'IPv6',
    'sha256':               'FileHash-SHA256',
    'sha-256':              'FileHash-SHA256',
    'md5':                  'FileHash-MD5',
    'sha1':                 'FileHash-SHA1',
    'sha-1':                'FileHash-SHA1',
    'email':                'email',
    'cve':                  'CVE',
    'social media account': 'URL',
    'proxy ip':             'IPv4',
    'proxy ipv4':           'IPv4',
    'proxy ipv6':           'IPv6',
}

# Map keywords in filename → origin country tags
ORIGIN_KEYWORDS = {
    'russia':   'Russia',
    'china':    'China',
    'iran':     'Iran',
    'pakistan': 'Pakistan',
    'belarus':  'Belarus',
    'india':    'India',
    'moldova':  'Moldova',
    'poland':   'Poland',
}

# Map keywords in title "Targeting X" → OTX targeted_countries values
# OTX uses ISO 3166 country names (3-char codes also accepted but names are clearer)
# Note: regions like "Sub-Saharan Africa" and "Eastern Europe" are NOT valid OTX country names
# For SSA reports we list the specific countries mentioned in the report body instead
TARGETED_COUNTRY_MAP = {
    'taiwan':           'Taiwan',
    'azerbaijan':       'Azerbaijan',
    'moldova':          'Moldova, Republic of',
    'poland':           'Poland',
    'india':            'India',
    'pakistan':         'Pakistan',
    'iraq':             'Iraq',
    'united states':    'United States of America',
    'france':           'France',
    'israel':           'Israel',
    'united kingdom':   'United Kingdom',
    'angola':           'Angola',
    'ghana':            'Ghana',
    'kenya':            'Kenya',
    'south africa':     'South Africa',
    'mali':             'Mali',
    'nigeria':          'Nigeria',
    'senegal':          'Senegal',
    'cameroon':         'Cameroon',
    'gabon':            'Gabon',
    'benin':            'Benin',
    'burkina faso':     'Burkina Faso',
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_front_matter(content):
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
    Extract everything between the Network Summary header and the
    Indicators of Compromise header, stripping Markdown formatting.
    Handles both ASCII apostrophe (') and Unicode right-single-quote (').
    """
    # Match the summary section header with any apostrophe variant
    # Then capture everything up to ## Indicators of Compromise
    pattern = (
        r"##\s+Meta[\u2019']s\s+Adversarial\s+Threat\s+Report\s+Network\s+Summary"
        r"\s*\n"
        r"(.*?)"
        r"(?=\n##\s+Indicators\s+of\s+Compromise|\Z)"
    )
    match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
    if not match:
        return ''

    raw = match.group(1)

    # Strip HTML image tags
    raw = re.sub(r'<img[^>]*>', '', raw)
    # Strip Markdown image syntax
    raw = re.sub(r'!\[.*?\]\(.*?\)', '', raw)
    # Convert Markdown links to plain text
    raw = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', raw)
    # Strip ### sub-headers (keep the text, remove the ### prefix)
    raw = re.sub(r'^#{2,}\s+', '', raw, flags=re.MULTILINE)
    # Collapse excessive blank lines
    raw = re.sub(r'\n{3,}', '\n\n', raw).strip()

    # OTX description field is capped at 1024 characters
    if len(raw) > 1024:
        raw = raw[:1021].rsplit(' ', 1)[0] + '...'

    return raw


def parse_iocs(content):
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

        if re.match(r'^[-:]+$', raw_value) or raw_type.lower() in ('indicator type', 'type'):
            continue

        raw_value = raw_value.replace('`', '').replace('[.]', '.')
        otx_type  = TYPE_MAP.get(raw_type.lower())

        if otx_type and raw_value:
            iocs.append({'indicator': raw_value, 'type': otx_type})

    return iocs


def extract_targeted_countries(title, body=''):
    """
    Parse targeted countries from the pulse title and, for regional titles
    (Sub-Saharan Africa, Eastern Europe), also scan the body text for
    specific country mentions. Returns a list of valid OTX country name strings.
    """
    countries = []

    # First try to extract from the 'Targeting X' phrase in the title
    match = re.search(r'[Tt]argeting\s+(.+)$', title)
    if match:
        targets_raw = match.group(1).strip().rstrip('.')
        parts = [p.strip().lower() for p in targets_raw.split(',')]
        for part in parts:
            for keyword, otx_name in TARGETED_COUNTRY_MAP.items():
                if keyword in part and otx_name not in countries:
                    countries.append(otx_name)

    # If title contains a regional term (SSA, Eastern Europe) or no countries found,
    # scan the body text for specific country mentions
    regional_terms = ['sub-saharan africa', 'ssa', 'eastern europe', 'africa']
    title_lower = title.lower()
    if not countries or any(t in title_lower for t in regional_terms):
        body_lower = body.lower()
        for keyword, otx_name in TARGETED_COUNTRY_MAP.items():
            if keyword in body_lower and otx_name not in countries:
                countries.append(otx_name)

    return countries


def build_tags(filename, title):
    stem = os.path.splitext(os.path.basename(filename))[0].lower()
    extra = []

    for kw, label in ORIGIN_KEYWORDS.items():
        if kw in stem and label not in extra:
            extra.append(label)

    # Also add targeted country names as tags
    for country in extract_targeted_countries(title):
        if country not in extra:
            extra.append(country)

    return BASE_TAGS + extra


def build_reference_url(filename):
    stem = os.path.splitext(os.path.basename(filename))[0]
    return f"{GITHUB_PAGES_BASE}/{stem}/"


def find_existing_pulse(otx, pulse_name):
    """Search the user's own pulses for one matching pulse_name. Returns ID or None."""
    try:
        # get_my_pulses fetches up to max_items pulses in one call (default 200)
        results = otx.get_my_pulses(max_items=1000)
        if results:
            for pulse in results:
                if pulse.get('name', '').strip() == pulse_name.strip():
                    return pulse['id']
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
        tags        = build_tags(filepath, title)
        countries   = extract_targeted_countries(title, body=summary)

        print(f"  Title:              {title}")
        print(f"  IOCs:               {len(iocs)}")
        print(f"  Summary length:     {len(summary)} chars")
        print(f"  Targeted countries: {countries}")
        print(f"  Tags:               {tags}")
        print(f"  Reference:          {ref_url}")

        if not iocs:
            print("  No IOCs in table — creating summary-only pulse (no indicators).")
            # Still create/update the pulse with summary and metadata, just no indicators

        print("  Checking for existing pulse...")
        existing_id = find_existing_pulse(otx, title)

        try:
            if existing_id:
                print(f"  Found existing pulse {existing_id} — updating...")
                otx.edit_pulse(
                    pulse_id=existing_id,
                    body={
                        'description':        summary,
                        'tags':               tags,
                        'references':         [ref_url],
                        'targeted_countries': countries,
                    }
                )
                otx.replace_pulse_indicators(
                    pulse_id=existing_id,
                    new_indicators=iocs
                )
                print("  Updated successfully.")
            else:
                print("  No existing pulse — creating new...")
                response = otx.create_pulse(
                    name=title,
                    public=True,
                    description=summary,
                    indicators=iocs,
                    tags=tags,
                    tlp='white',
                    references=[ref_url],
                    targeted_countries=countries,
                )
                print(f"  Created. Pulse ID: {response.get('id', 'unknown')}")

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
