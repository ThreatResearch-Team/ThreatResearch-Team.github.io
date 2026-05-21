#!/usr/bin/env python3
"""
otx_fetch_ids.py
----------------
ONE-TIME SCRIPT: Run this after the initial OTX sync to backfill the
otx_pulse_url field into each .md file's front matter and fix the
Cross-Links section with the correct OTX pulse URL.

Usage (run locally or as a one-time GitHub Action):
    OTX_API_KEY=<your_key> python3 .github/scripts/otx_fetch_ids.py

After running this, commit the updated .md files to the repo.
The main otx_sync.py will then use the stored pulse ID on all future runs.
"""

import os
import re
import sys
import glob

from OTXv2 import OTXv2

OTX_BASE_URL = "https://otx.alienvault.com/pulse"


def get_all_my_pulses(otx):
    """Fetch all pulses from the authenticated user's account."""
    print("Fetching all pulses from OTX account...")
    pulses = otx.get_my_pulses(max_items=1000)
    print(f"  Found {len(pulses)} pulse(s).")
    return pulses


def parse_front_matter_title(content):
    """Extract the title field from YAML front matter."""
    match = re.match(r'^---\s*\n(.*?)\n---\s*\n', content, re.DOTALL)
    if match:
        for line in match.group(1).splitlines():
            kv = re.match(r'^title:\s*"?(.*?)"?\s*$', line)
            if kv:
                return kv.group(1).strip()
    return None


def update_front_matter(content, pulse_url):
    """
    Insert or replace the otx_pulse_url field in the YAML front matter.
    Inserts it after the last existing front matter field.
    """
    fm_match = re.match(r'^(---\s*\n)(.*?)(\n---\s*\n)', content, re.DOTALL)
    if not fm_match:
        return content  # No front matter found, leave unchanged

    prefix   = fm_match.group(1)
    fm_body  = fm_match.group(2)
    suffix   = fm_match.group(3)
    rest     = content[fm_match.end():]

    # Remove any existing otx_pulse_url line
    fm_body = re.sub(r'\notx_pulse_url:.*', '', fm_body)
    fm_body = fm_body.rstrip()

    # Append the new field
    fm_body += f'\notx_pulse_url: "{pulse_url}"'

    return prefix + fm_body + suffix + rest


def update_cross_links(content, pulse_url):
    """
    Replace the AlienVault OTX Pulse line in the Cross-Links section
    with the correct URL.
    """
    new_line = f'- **AlienVault OTX Pulse:** [View on OTX]({pulse_url})'
    # Match the existing OTX line regardless of its current URL
    updated = re.sub(
        r'- \*\*AlienVault OTX Pulse:\*\*.*',
        new_line,
        content
    )
    return updated


def main():
    api_key = os.environ.get('OTX_API_KEY')
    if not api_key:
        print("ERROR: OTX_API_KEY environment variable is not set.")
        sys.exit(1)

    otx = OTXv2(api_key)
    pulses = get_all_my_pulses(otx)

    if not pulses:
        print("No pulses found in your OTX account. Nothing to do.")
        sys.exit(0)

    # Build a lookup: pulse name → pulse URL
    pulse_map = {}
    for p in pulses:
        name = p.get('name', '').strip()
        pid  = p.get('id', '')
        if name and pid:
            pulse_map[name] = f"{OTX_BASE_URL}/{pid}"

    print(f"\nPulse name → URL mapping:")
    for name, url in sorted(pulse_map.items()):
        print(f"  {name}")
        print(f"    {url}")

    # Process each .md file
    md_files = sorted(glob.glob('indicators/*.md'))
    if not md_files:
        print("\nNo .md files found in indicators/ — nothing to update.")
        sys.exit(0)

    print(f"\nProcessing {len(md_files)} .md file(s)...")
    updated_count = 0
    unmatched = []

    for filepath in md_files:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        title = parse_front_matter_title(content)
        if not title:
            print(f"  SKIP (no title): {filepath}")
            continue

        pulse_url = pulse_map.get(title)
        if not pulse_url:
            print(f"  NO MATCH: {filepath}")
            print(f"    Title: {title}")
            unmatched.append((filepath, title))
            continue

        # Update front matter and Cross-Links
        new_content = update_front_matter(content, pulse_url)
        new_content = update_cross_links(new_content, pulse_url)

        if new_content != content:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(f"  UPDATED: {filepath}")
            print(f"    → {pulse_url}")
            updated_count += 1
        else:
            print(f"  UNCHANGED: {filepath} (already up to date)")

    print(f"\nDone. {updated_count} file(s) updated.")

    if unmatched:
        print(f"\nWARNING: {len(unmatched)} file(s) had no matching OTX pulse:")
        for fp, t in unmatched:
            print(f"  {fp} (title: {t})")
        print("  These files may have no IOCs and were skipped during sync.")


if __name__ == '__main__':
    main()
