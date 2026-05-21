#!/usr/bin/env python3
"""
otx_sync.py
-----------
Reads all .md files in the indicators/ directory and creates or updates
AlienVault OTX pulses for each file that contains IOCs.

Key behaviours:
- Uses otx_pulse_url from front matter (if present) to update the correct pulse directly.
- On new pulse creation, writes the pulse URL back into the .md front matter
  and Cross-Links section, then commits and pushes to the repo.
- Handles Unicode right-single-quote (U+2019) in section header.
- Truncates description to OTX's 1024-character limit.
- Retries on transient API errors with exponential backoff.
- Skips files with no IOCs (OTX requires at least one indicator).
"""

import os
import re
import sys
import glob
import time
import subprocess

from OTXv2 import OTXv2

OTX_BASE_URL = "https://otx.alienvault.com/pulse"

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
# Retry helper
# ---------------------------------------------------------------------------

def with_retry(fn, retries=3, delay=10):
    """Call fn(), retrying up to `retries` times on any exception."""
    for attempt in range(1, retries + 1):
        try:
            return fn()
        except Exception as e:
            if attempt == retries:
                raise
            print(f"  Attempt {attempt} failed ({e}). Retrying in {delay}s...")
            time.sleep(delay)
            delay *= 2

# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def parse_front_matter(content):
    fm = {}
    match = re.match(r'^---\s*\n(.*?)\n---\s*\n', content, re.DOTALL)
    if match:
        for line in match.group(1).splitlines():
            # Handle both quoted and unquoted values, and keys with underscores
            kv = re.match(r'^([\w_]+):\s*"?(.*?)"?\s*$', line)
            if kv:
                fm[kv.group(1)] = kv.group(2)
    return fm


def update_front_matter(content, pulse_url):
    """Insert or replace the otx_pulse_url field in the YAML front matter."""
    fm_match = re.match(r'^(---\s*\n)(.*?)(\n---\s*\n)', content, re.DOTALL)
    if not fm_match:
        return content

    prefix  = fm_match.group(1)
    fm_body = fm_match.group(2)
    suffix  = fm_match.group(3)
    rest    = content[fm_match.end():]

    # Remove any existing otx_pulse_url line
    fm_body = re.sub(r'\notx_pulse_url:.*', '', fm_body)
    fm_body = fm_body.rstrip()
    fm_body += f'\notx_pulse_url: "{pulse_url}"'

    return prefix + fm_body + suffix + rest


def update_cross_links(content, pulse_url):
    """Replace the AlienVault OTX Pulse line in the Cross-Links section."""
    new_line = f'- **AlienVault OTX Pulse:** [View on OTX]({pulse_url})'
    return re.sub(r'- \*\*AlienVault OTX Pulse:\*\*.*', new_line, content)


def extract_summary(content):
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
    raw = re.sub(r'<img[^>]*>', '', raw)
    raw = re.sub(r'!\[.*?\]\(.*?\)', '', raw)
    raw = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', raw)
    raw = re.sub(r'^#{2,}\s+', '', raw, flags=re.MULTILINE)
    raw = re.sub(r'\n{3,}', '\n\n', raw).strip()

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
    countries = []
    match = re.search(r'[Tt]argeting\s+(.+)$', title)
    if match:
        targets_raw = match.group(1).strip().rstrip('.')
        parts = [p.strip().lower() for p in targets_raw.split(',')]
        for part in parts:
            for keyword, otx_name in TARGETED_COUNTRY_MAP.items():
                if keyword in part and otx_name not in countries:
                    countries.append(otx_name)

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
    for country in extract_targeted_countries(title):
        if country not in extra:
            extra.append(country)
    return BASE_TAGS + extra


def build_reference_url(filename):
    stem = os.path.splitext(os.path.basename(filename))[0]
    return f"{GITHUB_PAGES_BASE}/{stem}/"

# ---------------------------------------------------------------------------
# Git helper — write pulse URL back to .md and commit
# ---------------------------------------------------------------------------

def write_pulse_url_to_file(filepath, pulse_url):
    """Update the .md file with the new pulse URL in front matter and Cross-Links."""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    new_content = update_front_matter(content, pulse_url)
    new_content = update_cross_links(new_content, pulse_url)

    if new_content != content:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"  Wrote pulse URL to {filepath}")
        return True
    return False


def git_commit_and_push(filepaths):
    """Stage the given files, commit, and push back to origin."""
    try:
        subprocess.run(['git', 'config', 'user.email', 'github-actions@github.com'], check=True)
        subprocess.run(['git', 'config', 'user.name', 'GitHub Actions'], check=True)
        subprocess.run(['git', 'add'] + filepaths, check=True)
        result = subprocess.run(
            ['git', 'diff', '--cached', '--quiet'],
            capture_output=True
        )
        if result.returncode == 0:
            print("  No changes to commit.")
            return
        subprocess.run(
            ['git', 'commit', '-m', 'chore: update OTX pulse URLs in indicator files [skip ci]'],
            check=True
        )
        subprocess.run(['git', 'push'], check=True)
        print("  Committed and pushed pulse URL updates.")
    except subprocess.CalledProcessError as e:
        print(f"  WARNING: git operation failed: {e}. Pulse URLs were not saved to repo.")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def sync_to_otx(api_key, md_files):
    otx = OTXv2(api_key)
    files_to_commit = []

    for filepath in sorted(md_files):
        print(f"\n{'='*60}")
        print(f"Processing: {filepath}")

        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        fm        = parse_front_matter(content)
        title     = fm.get('title', os.path.splitext(os.path.basename(filepath))[0])
        summary   = extract_summary(content)
        iocs      = parse_iocs(content)
        ref_url   = build_reference_url(filepath)
        tags      = build_tags(filepath, title)
        countries = extract_targeted_countries(title, body=summary)

        # Check for stored pulse ID in front matter
        stored_pulse_url = fm.get('otx_pulse_url', '').strip()
        stored_pulse_id  = None
        if stored_pulse_url:
            id_match = re.search(r'/pulse/([a-f0-9]+)$', stored_pulse_url)
            if id_match:
                stored_pulse_id = id_match.group(1)

        print(f"  Title:              {title}")
        print(f"  IOCs:               {len(iocs)}")
        print(f"  Summary length:     {len(summary)} chars")
        print(f"  Targeted countries: {countries}")
        print(f"  Stored pulse ID:    {stored_pulse_id or 'none'}")

        if not iocs:
            print("  No IOCs found — skipping (OTX requires at least one indicator).")
            continue

        try:
            if stored_pulse_id:
                # Use the stored ID directly — no name search needed
                print(f"  Using stored pulse ID {stored_pulse_id} — updating...")
                with_retry(lambda: otx.edit_pulse(
                    pulse_id=stored_pulse_id,
                    body={
                        'description':        summary,
                        'tags':               tags,
                        'references':         [ref_url],
                        'targeted_countries': countries,
                    }
                ))
                with_retry(lambda: otx.replace_pulse_indicators(
                    pulse_id=stored_pulse_id,
                    new_indicators=iocs
                ))
                print("  Updated successfully.")

            else:
                # No stored ID — create a new pulse
                print("  No stored pulse ID — creating new pulse...")
                response = with_retry(lambda: otx.create_pulse(
                    name=title,
                    public=True,
                    description=summary,
                    indicators=iocs,
                    tags=tags,
                    tlp='white',
                    references=[ref_url],
                    targeted_countries=countries,
                ))
                new_id  = response.get('id', '')
                new_url = f"{OTX_BASE_URL}/{new_id}"
                print(f"  Created. Pulse URL: {new_url}")

                # Write the pulse URL back into the .md file
                if write_pulse_url_to_file(filepath, new_url):
                    files_to_commit.append(filepath)

        except Exception as e:
            print(f"  ERROR: {e}")
            sys.exit(1)

        time.sleep(2)

    # Commit all updated .md files in one push
    if files_to_commit:
        print(f"\nCommitting pulse URL updates for {len(files_to_commit)} file(s)...")
        git_commit_and_push(files_to_commit)

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
